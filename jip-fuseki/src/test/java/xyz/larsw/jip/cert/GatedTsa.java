package xyz.larsw.jip.cert;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.URI;
import java.time.Clock;
import java.time.Duration;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import com.sun.net.httpserver.HttpServer;

/**
 * An RFC 3161 endpoint for tests that holds every reply until {@link #open()} is called, so a
 * test can observe a certificate while its timestamp is pending. Before that, requests wait
 * (up to 30 s) and then fail with HTTP 503.
 */
public final class GatedTsa implements AutoCloseable {
    private final TestTsa tsa = new TestTsa();
    private final CountDownLatch gate = new CountDownLatch(1);
    private final AtomicInteger requests = new AtomicInteger();
    private final HttpServer server;
    private final URI url;

    public GatedTsa() throws IOException {
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.setExecutor(java.util.concurrent.Executors.newCachedThreadPool());
        server.createContext("/tsa", exchange -> {
            requests.incrementAndGet();
            try ( InputStream in = exchange.getRequestBody(); OutputStream out = exchange.getResponseBody() ) {
                byte[] request = in.readAllBytes();
                boolean open;
                try {
                    open = gate.await(30, TimeUnit.SECONDS);
                } catch (InterruptedException ex) {
                    open = false;
                }
                if ( !open ) {
                    exchange.sendResponseHeaders(503, -1);
                    return;
                }
                byte[] body;
                try {
                    body = tsa.reply(request);
                } catch (Exception ex) {
                    exchange.sendResponseHeaders(400, -1);
                    return;
                }
                exchange.sendResponseHeaders(200, body.length);
                out.write(body);
            }
        });
        server.start();
        url = URI.create("http://127.0.0.1:" + server.getAddress().getPort() + "/tsa");
    }

    public URI url() {
        return url;
    }

    public TestTsa tsa() {
        return tsa;
    }

    public int requests() {
        return requests.get();
    }

    /** Let replies through. */
    public void open() {
        gate.countDown();
    }

    @Override
    public void close() {
        open();
        server.stop(0);
    }

    /** Asynchronous authorities with a short retry backoff, for tests. */
    public static TimestampAuthorities async(List<URI> urls, TimestampAuthorities.Policy policy, Duration maxWait) {
        return TimestampAuthorities.of(urls, policy, TimestampAuthorities.Mode.ASYNC, Duration.ofSeconds(35), maxWait,
                                       List.of(Duration.ofMillis(100)), Clock.systemUTC());
    }
}

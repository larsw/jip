package xyz.larsw.jip.cert;

import static org.junit.jupiter.api.Assertions.*;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.URI;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Optional;

import com.sun.net.httpserver.HttpServer;
import org.apache.jena.sparql.util.Context;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import xyz.larsw.jip.JIP;

class TimestampAuthoritiesTest {

    static final byte[] IMPRINT = Rfc3161.sha256("certificate signature".getBytes());
    static final Duration TIMEOUT = Duration.ofSeconds(2);

    TestTsa good;
    URI goodUrl;
    HttpServer broken;
    URI brokenUrl;
    URI deadUrl;

    /** A clock the test moves forward. */
    static final class MovableClock extends Clock {
        Instant now = Instant.parse("2026-11-19T12:00:00Z");

        @Override
        public Instant instant() {
            return now;
        }

        @Override
        public ZoneOffset getZone() {
            return ZoneOffset.UTC;
        }

        @Override
        public Clock withZone(java.time.ZoneId zone) {
            return this;
        }
    }

    @BeforeEach
    void setup() throws IOException {
        good = new TestTsa();
        goodUrl = good.start();
        broken = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        broken.createContext("/", ex -> ex.sendResponseHeaders(503, -1));
        broken.start();
        brokenUrl = URI.create("http://127.0.0.1:" + broken.getAddress().getPort() + "/tsa");
        try ( ServerSocket s = new ServerSocket(0) ) {
            deadUrl = URI.create("http://127.0.0.1:" + s.getLocalPort() + "/tsa");   // closed again: refused
        }
    }

    @AfterEach
    void cleanup() {
        good.close();
        broken.stop(0);
        TimestampAuthorities.resetForTesting();
    }

    @Test
    void firstAuthorityThatAnswersWins() {
        TimestampAuthorities tsa = TimestampAuthorities.of(List.of(deadUrl, brokenUrl, goodUrl), TimestampAuthorities.Policy.OPTIONAL, TimestampAuthorities.Mode.SYNC, TIMEOUT, TimestampAuthorities.DEFAULT_MAX_WAIT);
        Optional<TimestampAuthorities.Stamp> stamp = tsa.stamp(IMPRINT);
        assertTrue(stamp.isPresent());
        assertEquals(goodUrl, stamp.get().authority());
        Rfc3161.TokenCheck check = Rfc3161.verify(stamp.get().token(), IMPRINT, Optional.of(good.anchors()));
        assertTrue(check.acceptable(), () -> check.problems().toString());
    }

    @Test
    void failedAuthoritiesAreTriedLastDuringTheCooldown() {
        MovableClock clock = new MovableClock();
        TimestampAuthorities tsa = TimestampAuthorities.of(List.of(brokenUrl, goodUrl), TimestampAuthorities.Policy.OPTIONAL, TimestampAuthorities.Mode.SYNC, TIMEOUT,
                TimestampAuthorities.DEFAULT_MAX_WAIT, List.of(Duration.ofSeconds(5)), clock);
        assertEquals(List.of(brokenUrl, goodUrl), tsa.order());
        assertTrue(tsa.stamp(IMPRINT).isPresent());
        assertEquals(List.of(goodUrl, brokenUrl), tsa.order(), "broken authority demoted");

        clock.now = clock.now.plus(TimestampAuthorities.COOLDOWN).plusSeconds(1);
        assertEquals(List.of(brokenUrl, goodUrl), tsa.order(), "priority restored after the cooldown");
    }

    @Test
    void allFailingGivesNoStamp() {
        TimestampAuthorities tsa = TimestampAuthorities.of(List.of(deadUrl, brokenUrl), TimestampAuthorities.Policy.REQUIRED, TimestampAuthorities.Mode.SYNC, TIMEOUT, TimestampAuthorities.DEFAULT_MAX_WAIT);
        assertTrue(tsa.stamp(IMPRINT).isEmpty());
    }

    @Test
    void configurationFromContext() {
        Context cxt = new Context();
        assertTrue(TimestampAuthorities.fromContext(cxt).isEmpty(), "off unless configured");

        cxt.set(JIP.symTimestampAuthorities, " " + deadUrl + ",\n " + goodUrl + " ");
        cxt.set(JIP.symTimestampPolicy, "REQUIRED");
        cxt.set(JIP.symTimestampTimeout, "1500");
        TimestampAuthorities tsa = TimestampAuthorities.fromContext(cxt).orElseThrow();
        assertEquals(List.of(deadUrl, goodUrl), tsa.authorities());
        assertEquals(TimestampAuthorities.Policy.REQUIRED, tsa.policy());
        assertEquals(Duration.ofMillis(1500), tsa.timeout());
        assertSame(tsa, TimestampAuthorities.fromContext(cxt).orElseThrow(), "shared per configuration (cooldown state)");

        cxt.set(JIP.symTimestampPolicy, "sometimes");
        assertThrows(IllegalArgumentException.class, () -> TimestampAuthorities.fromContext(cxt));
        cxt.set(JIP.symTimestampPolicy, "optional");
        cxt.set(JIP.symTimestampAuthorities, "ftp://tsa.example/");
        assertThrows(IllegalArgumentException.class, () -> TimestampAuthorities.fromContext(cxt));
    }
}

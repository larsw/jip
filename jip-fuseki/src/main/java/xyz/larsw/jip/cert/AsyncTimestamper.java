package xyz.larsw.jip.cert;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

import org.apache.jena.graph.Graph;
import org.apache.jena.graph.GraphMemFactory;
import org.apache.jena.graph.Node;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Fetches timestamps for pending certificates in the background, one at a time (public TSAs
 * limit request rates), and retries with backoff.
 * <ul>
 * <li>Success: the token is added to the stored certificate and the pending mark cleared.</li>
 * <li>Failure, policy {@code optional}: retried until {@code maxWait} has passed since the
 * certificate was stored, then released without a timestamp.</li>
 * <li>Failure, policy {@code required}: retried indefinitely; the certificate stays pending.</li>
 * </ul>
 * The pending state lives in the {@link CertificateStore}, so nothing is lost if the process
 * stops; {@link #resume} picks the certificates up again.
 */
final class AsyncTimestamper {
    private static final Logger LOG = LoggerFactory.getLogger(AsyncTimestamper.class);

    /** Delays before the 2nd, 3rd, ... attempt; the last one repeats. */
    static final List<Duration> DEFAULT_BACKOFF = List.of(Duration.ofSeconds(5), Duration.ofSeconds(15), Duration.ofSeconds(30),
                                                          Duration.ofMinutes(1), Duration.ofMinutes(2), Duration.ofMinutes(5),
                                                          Duration.ofMinutes(10));

    private record Job(CertificateStore store, Node certificate, Instant since, int attempt) {}

    private final TimestampAuthorities authorities;
    private final List<Duration> backoff;
    private final Clock clock;
    private final ScheduledExecutorService executor;
    /** Next attempt per certificate, for Retry-After and to avoid queueing a certificate twice. */
    private final Map<Node, Instant> nextAttempt = new ConcurrentHashMap<>();

    AsyncTimestamper(TimestampAuthorities authorities, List<Duration> backoff, Clock clock) {
        if ( backoff.isEmpty() )
            throw new IllegalArgumentException("Empty backoff");
        this.authorities = authorities;
        this.backoff = List.copyOf(backoff);
        this.clock = clock;
        this.executor = Executors.newSingleThreadScheduledExecutor(r -> {
            Thread t = new Thread(r, "jip-timestamper");
            t.setDaemon(true);
            return t;
        });
    }

    /** Queue a certificate that was stored with {@link CertificateStore#storePending}. */
    void submit(CertificateStore store, Node certificate, Instant since) {
        schedule(new Job(store, certificate, since, 0), Duration.ZERO);
    }

    /** Queue every pending certificate in the store that isn't queued yet; returns how many. */
    int resume(CertificateStore store) {
        int n = 0;
        for ( Node cert : store.pending() ) {
            if ( nextAttempt.containsKey(cert) )
                continue;
            Instant since = store.pendingSince(cert).orElse(clock.instant());
            schedule(new Job(store, cert, since, 0), Duration.ZERO);
            n++;
        }
        return n;
    }

    /** Time until the next attempt for a queued certificate. */
    Optional<Duration> untilNextAttempt(Node certificate) {
        Instant next = nextAttempt.get(certificate);
        if ( next == null )
            return Optional.empty();
        Duration d = Duration.between(clock.instant(), next);
        return Optional.of(d.isNegative() ? Duration.ZERO : d);
    }

    boolean isQueued(Node certificate) {
        return nextAttempt.containsKey(certificate);
    }

    private void schedule(Job job, Duration delay) {
        Instant at = clock.instant().plus(delay);
        if ( job.attempt() == 0 && nextAttempt.putIfAbsent(job.certificate(), at) != null )
            return;   // already queued
        nextAttempt.put(job.certificate(), at);
        executor.schedule(() -> run(job), delay.toMillis(), TimeUnit.MILLISECONDS);
    }

    private void run(Job job) {
        Node cert = job.certificate();
        try {
            if ( job.store().pendingSince(cert).isEmpty() ) {
                nextAttempt.remove(cert);   // finished elsewhere
                return;
            }
            Optional<Graph> graph = job.store().get(cert);
            if ( graph.isEmpty() ) {
                LOG.warn("Pending certificate {} is not in the store; dropping it", cert.getURI());
                job.store().completePending(cert, GraphMemFactory.createDefaultGraph());
                nextAttempt.remove(cert);
                return;
            }
            Optional<TimestampAuthorities.Stamp> stamp = authorities.stamp(CertificateTimestamps.messageImprint(graph.get(), cert));
            if ( stamp.isPresent() ) {
                Graph additions = GraphMemFactory.createDefaultGraph();
                CertificateTimestamps.attach(additions, cert, stamp.get().token(), stamp.get().authority().toString());
                boolean done = job.store().completePending(cert, additions);
                nextAttempt.remove(cert);
                if ( done )
                    LOG.info("Timestamped certificate {} by {} after {} attempt(s)", cert.getURI(), stamp.get().authority(),
                             job.attempt() + 1);
                return;
            }
        } catch (RuntimeException ex) {
            LOG.warn("Timestamping certificate {} failed: {}", cert.getURI(), ex.toString());
        }
        retry(job);
    }

    private void retry(Job job) {
        Node cert = job.certificate();
        Duration delay = backoff.get(Math.min(job.attempt(), backoff.size() - 1));
        boolean optional = authorities.policy() == TimestampAuthorities.Policy.OPTIONAL;
        if ( optional && !clock.instant().plus(delay).isBefore(job.since().plus(authorities.maxWait())) ) {
            try {
                job.store().completePending(cert, GraphMemFactory.createDefaultGraph());
                LOG.warn("Certificate {} released without an RFC 3161 timestamp: no authority answered within {} s",
                         cert.getURI(), authorities.maxWait().toSeconds());
            } catch (RuntimeException ex) {
                LOG.warn("Releasing certificate {} failed: {}", cert.getURI(), ex.toString());
            }
            nextAttempt.remove(cert);
            return;
        }
        schedule(new Job(job.store(), cert, job.since(), job.attempt() + 1), delay);
    }
}

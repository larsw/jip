package xyz.larsw.jip.attestation;

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
 * Fetches timestamps for pending attestations in the background, one at a time (public TSAs
 * limit request rates), and retries with backoff.
 * <ul>
 * <li>Success: the token is added to the stored attestation and the pending mark cleared.</li>
 * <li>Failure, policy {@code optional}: retried until {@code maxWait} has passed since the
 * attestation was stored, then released without a timestamp.</li>
 * <li>Failure, policy {@code required}: retried indefinitely; the attestation stays pending.</li>
 * </ul>
 * The pending state lives in the {@link AttestationStore}, so nothing is lost if the process
 * stops; {@link #resume} picks the attestations up again.
 */
final class AsyncTimestamper {
    private static final Logger LOG = LoggerFactory.getLogger(AsyncTimestamper.class);

    /** Delays before the 2nd, 3rd, ... attempt; the last one repeats. */
    static final List<Duration> DEFAULT_BACKOFF = List.of(Duration.ofSeconds(5), Duration.ofSeconds(15), Duration.ofSeconds(30),
                                                          Duration.ofMinutes(1), Duration.ofMinutes(2), Duration.ofMinutes(5),
                                                          Duration.ofMinutes(10));

    private record Job(AttestationStore store, Node attestation, Instant since, int attempt) {}

    private final TimestampAuthorities authorities;
    private final List<Duration> backoff;
    private final Clock clock;
    private final ScheduledExecutorService executor;
    /** Next attempt per attestation, for Retry-After and to avoid queueing an attestation twice. */
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

    /** Queue an attestation that was stored with {@link AttestationStore#storePending}. */
    void submit(AttestationStore store, Node attestation, Instant since) {
        schedule(new Job(store, attestation, since, 0), Duration.ZERO);
    }

    /** Queue every pending attestation in the store that isn't queued yet; returns how many. */
    int resume(AttestationStore store) {
        int n = 0;
        for ( Node attestationIri : store.pending() ) {
            if ( nextAttempt.containsKey(attestationIri) )
                continue;
            Instant since = store.pendingSince(attestationIri).orElse(clock.instant());
            schedule(new Job(store, attestationIri, since, 0), Duration.ZERO);
            n++;
        }
        return n;
    }

    /** Time until the next attempt for a queued attestation. */
    Optional<Duration> untilNextAttempt(Node attestation) {
        Instant next = nextAttempt.get(attestation);
        if ( next == null )
            return Optional.empty();
        Duration d = Duration.between(clock.instant(), next);
        return Optional.of(d.isNegative() ? Duration.ZERO : d);
    }

    boolean isQueued(Node attestation) {
        return nextAttempt.containsKey(attestation);
    }

    private void schedule(Job job, Duration delay) {
        Instant at = clock.instant().plus(delay);
        if ( job.attempt() == 0 && nextAttempt.putIfAbsent(job.attestation(), at) != null )
            return;   // already queued
        nextAttempt.put(job.attestation(), at);
        executor.schedule(() -> run(job), delay.toMillis(), TimeUnit.MILLISECONDS);
    }

    private void run(Job job) {
        Node attestationIri = job.attestation();
        try {
            if ( job.store().pendingSince(attestationIri).isEmpty() ) {
                nextAttempt.remove(attestationIri);   // finished elsewhere
                return;
            }
            Optional<Graph> graph = job.store().get(attestationIri);
            if ( graph.isEmpty() ) {
                LOG.warn("Pending attestation {} is not in the store; dropping it", attestationIri.getURI());
                job.store().completePending(attestationIri, GraphMemFactory.createDefaultGraph());
                nextAttempt.remove(attestationIri);
                return;
            }
            Optional<TimestampAuthorities.Stamp> stamp = authorities.stamp(AttestationTimestamps.messageImprint(graph.get(), attestationIri));
            if ( stamp.isPresent() ) {
                Graph additions = GraphMemFactory.createDefaultGraph();
                AttestationTimestamps.attach(additions, attestationIri, stamp.get().token(), stamp.get().authority().toString());
                boolean done = job.store().completePending(attestationIri, additions);
                nextAttempt.remove(attestationIri);
                if ( done )
                    LOG.info("Timestamped attestation {} by {} after {} attempt(s)", attestationIri.getURI(), stamp.get().authority(),
                             job.attempt() + 1);
                return;
            }
        } catch (RuntimeException ex) {
            LOG.warn("Timestamping attestation {} failed: {}", attestationIri.getURI(), ex.toString());
        }
        retry(job);
    }

    private void retry(Job job) {
        Node attestationIri = job.attestation();
        Duration delay = backoff.get(Math.min(job.attempt(), backoff.size() - 1));
        boolean optional = authorities.policy() == TimestampAuthorities.Policy.OPTIONAL;
        if ( optional && !clock.instant().plus(delay).isBefore(job.since().plus(authorities.maxWait())) ) {
            try {
                job.store().completePending(attestationIri, GraphMemFactory.createDefaultGraph());
                LOG.warn("Attestation {} released without an RFC 3161 timestamp: no authority answered within {} s",
                         attestationIri.getURI(), authorities.maxWait().toSeconds());
            } catch (RuntimeException ex) {
                LOG.warn("Releasing attestation {} failed: {}", attestationIri.getURI(), ex.toString());
            }
            nextAttempt.remove(attestationIri);
            return;
        }
        schedule(new Job(job.store(), attestationIri, job.since(), job.attempt() + 1), delay);
    }
}

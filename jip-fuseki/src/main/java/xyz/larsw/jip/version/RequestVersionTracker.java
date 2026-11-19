package xyz.larsw.jip.version;

import java.util.Optional;
import java.util.UUID;

/**
 * Per-thread record of the data version a request read or committed, used to set the
 * {@code X-Dataset-Version} / {@code X-Dataset-Id} response headers.
 * <p>
 * Tracking is only active between {@link #start()} and {@link #stop()} (called by the HTTP
 * filter), so non-request threads do not accumulate state.
 * <ul>
 * <li>Transaction begin (read or write): the snapshot version.</li>
 * <li>Write commit: the version this request committed.</li>
 * <li>Write abort: cleared (no header).</li>
 * </ul>
 * The most recent event wins.
 */
public final class RequestVersionTracker {
    private RequestVersionTracker() {}

    /** What the request saw: database id, version and whether it was committed by this request. */
    public record Observation(UUID databaseId, long version, boolean committedByRequest) {}

    private static final class Holder {
        Observation observation;
    }

    private static final ThreadLocal<Holder> HOLDER = new ThreadLocal<>();

    /** Start tracking on the current thread. */
    public static void start() {
        HOLDER.set(new Holder());
    }

    /** Stop tracking on the current thread. */
    public static void stop() {
        HOLDER.remove();
    }

    /** The current observation, if tracking is active and something was observed. */
    public static Optional<Observation> current() {
        Holder h = HOLDER.get();
        return h == null ? Optional.empty() : Optional.ofNullable(h.observation);
    }

    static void observeBegin(DataVersionComponent component, long version) {
        Holder h = HOLDER.get();
        if ( h != null )
            h.observation = new Observation(component.databaseId(), version, false);
    }

    static void observeCommit(DataVersionComponent component, long version) {
        Holder h = HOLDER.get();
        if ( h != null )
            h.observation = new Observation(component.databaseId(), version, true);
    }

    static void observeAbort(DataVersionComponent component) {
        Holder h = HOLDER.get();
        if ( h != null && h.observation != null && h.observation.databaseId().equals(component.databaseId()) )
            h.observation = null;
    }
}

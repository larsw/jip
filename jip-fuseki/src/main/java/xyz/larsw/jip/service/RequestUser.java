package xyz.larsw.jip.service;

import java.util.Locale;
import java.util.Optional;

import org.apache.jena.sparql.util.Context;
import xyz.larsw.jip.JIP;
import xyz.larsw.jip.attestation.Requester;

/**
 * The authenticated user of the request being served, for the attest SERVICE.
 * <p>
 * Fuseki doesn't put the HTTP user into the query's context, but it runs the query on the
 * request's thread, so {@link xyz.larsw.jip.fuseki.RequesterFilter} records it here per thread.
 * Embedded use can put a {@link Requester} in the query context under {@code jip:requestUser}
 * instead; the context wins.
 * <p>
 * Recording is on by default. {@code PROVENANCE_RECORD_REQUESTER=false} (environment) or the
 * server context setting {@code jip:recordRequester false} turns it off; attestations are then
 * anonymous even for authenticated requests.
 */
public final class RequestUser {
    private RequestUser() {}

    public static final String ENV_RECORD = "PROVENANCE_RECORD_REQUESTER";

    private static final ThreadLocal<Requester> CURRENT = new ThreadLocal<>();

    public static void set(Requester requester) {
        CURRENT.set(requester);
    }

    public static void clear() {
        CURRENT.remove();
    }

    /** The requester to record in an attestation made with this context, if any. */
    public static Optional<Requester> forAttestation(Context context) {
        if ( !recording(context) )
            return Optional.empty();
        Object v = context == null ? null : context.get(JIP.symRequestUser);
        if ( v instanceof Requester r )
            return Optional.of(r);
        return Optional.ofNullable(CURRENT.get());
    }

    static boolean recording(Context context) {
        String env = System.getenv(ENV_RECORD);
        Object v = env != null ? env : (context == null ? null : context.get(JIP.symRecordRequester));
        if ( v == null )
            return true;
        if ( v instanceof Boolean b )
            return b;
        String s = v instanceof org.apache.jena.graph.Node n && n.isLiteral() ? n.getLiteralLexicalForm() : v.toString();
        return !s.strip().toLowerCase(Locale.ROOT).equals("false");
    }
}

package xyz.larsw.jip.cert;

import java.io.IOException;
import java.math.BigInteger;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

import org.apache.jena.graph.Node;
import org.apache.jena.sparql.util.Context;
import org.bouncycastle.tsp.TSPException;
import org.bouncycastle.tsp.TimeStampRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import xyz.larsw.jip.JIP;

/**
 * RFC 3161 time-stamping authorities, tried in priority order.
 * <p>
 * For each certificate the authorities are asked one at a time, each with its own timeout; the
 * first valid token wins. An authority that fails is moved behind the others for
 * {@link #COOLDOWN}, so one that is down does not delay every certificate, but it is still
 * tried if all others fail too.
 * <p>
 * Configuration, read by {@link #fromContext}; each environment variable, when set (even to an
 * empty value), overrides the context setting:
 * <table>
 * <tr><th>Context ({@code ja:context})</th><th>Environment</th><th>Value</th></tr>
 * <tr><td>{@code jip:timestampAuthorities}</td><td>{@value #ENV_URLS}</td>
 *     <td>TSA URLs in priority order, separated by whitespace or commas; empty: no timestamps</td></tr>
 * <tr><td>{@code jip:timestampPolicy}</td><td>{@value #ENV_POLICY}</td>
 *     <td>{@code optional} (default): issue the certificate without a timestamp if no TSA
 *     answers; {@code required}: fail the certification</td></tr>
 * <tr><td>{@code jip:timestampTimeout}</td><td>{@value #ENV_TIMEOUT}</td>
 *     <td>per-TSA timeout in milliseconds (default 5000)</td></tr>
 * </table>
 */
public final class TimestampAuthorities {
    private static final Logger LOG = LoggerFactory.getLogger(TimestampAuthorities.class);

    public static final String ENV_URLS = "PROVENANCE_TSA_URLS";
    public static final String ENV_POLICY = "PROVENANCE_TSA_POLICY";
    public static final String ENV_TIMEOUT = "PROVENANCE_TSA_TIMEOUT";

    public static final Duration DEFAULT_TIMEOUT = Duration.ofSeconds(5);
    /** How long a failed authority is tried last. */
    public static final Duration COOLDOWN = Duration.ofSeconds(60);
    /** Largest reply accepted (a token with a certificate chain is a few KB). */
    static final int MAX_REPLY = 256 * 1024;

    public enum Policy { OPTIONAL, REQUIRED }

    /** A token and the authority that issued it. */
    public record Stamp(URI authority, byte[] token) {}

    private static final Map<String, TimestampAuthorities> byConfig = new ConcurrentHashMap<>();
    private static final SecureRandom RANDOM = new SecureRandom();

    private final List<URI> authorities;
    private final Policy policy;
    private final Duration timeout;
    private final HttpClient http;
    private final Clock clock;
    private final Map<URI, Instant> coolingUntil = new ConcurrentHashMap<>();

    private TimestampAuthorities(List<URI> authorities, Policy policy, Duration timeout, Clock clock) {
        if ( authorities.isEmpty() )
            throw new IllegalArgumentException("No timestamp authorities");
        for ( URI u : authorities ) {
            String scheme = u.getScheme() == null ? "" : u.getScheme().toLowerCase(Locale.ROOT);
            if ( !scheme.equals("http") && !scheme.equals("https") )
                throw new IllegalArgumentException("Timestamp authority must be an http(s) URL: " + u);
        }
        this.authorities = List.copyOf(authorities);
        this.policy = policy;
        this.timeout = timeout;
        this.clock = clock;
        this.http = HttpClient.newBuilder()
                .connectTimeout(timeout)
                .followRedirects(HttpClient.Redirect.NORMAL)
                .build();
    }

    public static TimestampAuthorities of(List<URI> authorities, Policy policy, Duration timeout) {
        return new TimestampAuthorities(authorities, policy, timeout, Clock.systemUTC());
    }

    /** For tests: a clock to drive the cooldown. */
    static TimestampAuthorities of(List<URI> authorities, Policy policy, Duration timeout, Clock clock) {
        return new TimestampAuthorities(authorities, policy, timeout, clock);
    }

    public List<URI> authorities() {
        return authorities;
    }

    public Policy policy() {
        return policy;
    }

    public Duration timeout() {
        return timeout;
    }

    /**
     * The configured authorities, if any. The context may also hold a
     * {@link TimestampAuthorities} instance under {@code jip:timestampAuthorities} (embedded use,
     * tests). Instances are shared per configuration, so the cooldown state is process-wide.
     *
     * @throws IllegalArgumentException if the configuration is malformed
     */
    public static Optional<TimestampAuthorities> fromContext(Context context) {
        String envUrls = System.getenv(ENV_URLS);
        if ( envUrls == null ) {
            Object v = context == null ? null : context.get(JIP.symTimestampAuthorities);
            if ( v instanceof TimestampAuthorities t )
                return Optional.of(t);
        }
        String urls = envUrls != null ? envUrls : setting(context, JIP.symTimestampAuthorities);
        if ( urls == null || urls.isBlank() )
            return Optional.empty();
        String policy = Optional.ofNullable(System.getenv(ENV_POLICY)).orElse(setting(context, JIP.symTimestampPolicy));
        String timeout = Optional.ofNullable(System.getenv(ENV_TIMEOUT)).orElse(setting(context, JIP.symTimestampTimeout));
        String key = urls.strip() + "|" + policy + "|" + timeout;
        return Optional.of(byConfig.computeIfAbsent(key, k -> of(parseUrls(urls), parsePolicy(policy), parseTimeout(timeout))));
    }

    static List<URI> parseUrls(String urls) {
        List<URI> out = new ArrayList<>();
        for ( String s : urls.strip().split("[\\s,]+") ) {
            if ( s.isEmpty() )
                continue;
            try {
                out.add(URI.create(s));
            } catch (IllegalArgumentException ex) {
                throw new IllegalArgumentException("Bad timestamp authority URL: " + s, ex);
            }
        }
        return out;
    }

    static Policy parsePolicy(String s) {
        if ( s == null || s.isBlank() )
            return Policy.OPTIONAL;
        return switch (s.strip().toLowerCase(Locale.ROOT)) {
            case "optional" -> Policy.OPTIONAL;
            case "required" -> Policy.REQUIRED;
            default -> throw new IllegalArgumentException("Timestamp policy must be 'optional' or 'required': " + s);
        };
    }

    static Duration parseTimeout(String s) {
        if ( s == null || s.isBlank() )
            return DEFAULT_TIMEOUT;
        try {
            long ms = Long.parseLong(s.strip());
            if ( ms <= 0 )
                throw new IllegalArgumentException("Timestamp timeout must be positive: " + s);
            return Duration.ofMillis(ms);
        } catch (NumberFormatException ex) {
            throw new IllegalArgumentException("Timestamp timeout must be milliseconds: " + s, ex);
        }
    }

    private static String setting(Context context, org.apache.jena.sparql.util.Symbol symbol) {
        Object v = context == null ? null : context.get(symbol);
        if ( v == null )
            return null;
        if ( v instanceof Node n )
            return n.isLiteral() ? n.getLiteralLexicalForm() : n.isURI() ? n.getURI() : null;
        return v.toString();
    }

    /** The order the authorities are tried in now: available ones by priority, then cooling ones. */
    List<URI> order() {
        Instant now = clock.instant();
        List<URI> ready = new ArrayList<>();
        List<URI> cooling = new ArrayList<>();
        for ( URI u : authorities ) {
            Instant until = coolingUntil.get(u);
            (until != null && now.isBefore(until) ? cooling : ready).add(u);
        }
        ready.addAll(cooling);
        return ready;
    }

    /**
     * Ask the authorities, in {@link #order()}, for a token over {@code sha256Imprint}.
     *
     * @return the first valid token, or empty if every authority failed
     */
    public Optional<Stamp> stamp(byte[] sha256Imprint) {
        List<String> failures = new ArrayList<>();
        for ( URI u : order() ) {
            try {
                byte[] token = request(u, sha256Imprint);
                if ( coolingUntil.remove(u) != null )
                    LOG.info("Timestamp authority {} is answering again", u);
                if ( !failures.isEmpty() )
                    LOG.info("Timestamped by fallback authority {} after: {}", u, failures);
                return Optional.of(new Stamp(u, token));
            } catch (InterruptedException ex) {
                Thread.currentThread().interrupt();
                failures.add(u + ": interrupted");
                break;
            } catch (IOException | TSPException | RuntimeException ex) {
                String msg = ex.getMessage() == null ? ex.getClass().getSimpleName() : ex.getMessage();
                failures.add(u + ": " + msg);
                coolingUntil.put(u, clock.instant().plus(COOLDOWN));
                LOG.warn("Timestamp authority {} failed: {}", u, msg);
            }
        }
        LOG.warn("No timestamp authority answered: {}", failures);
        return Optional.empty();
    }

    private byte[] request(URI authority, byte[] imprint) throws IOException, InterruptedException, TSPException {
        TimeStampRequest req = Rfc3161.request(imprint, new BigInteger(64, RANDOM));
        HttpRequest httpReq = HttpRequest.newBuilder(authority)
                .timeout(timeout)
                .header("Content-Type", Rfc3161.MEDIA_TYPE_QUERY)
                .header("Accept", Rfc3161.MEDIA_TYPE_REPLY)
                .POST(HttpRequest.BodyPublishers.ofByteArray(req.getEncoded()))
                .build();
        HttpResponse<byte[]> resp = http.send(httpReq, HttpResponse.BodyHandlers.ofByteArray());
        if ( resp.statusCode() != 200 )
            throw new IOException("HTTP " + resp.statusCode());
        byte[] body = resp.body();
        if ( body.length > MAX_REPLY )
            throw new IOException("Reply too large (" + body.length + " bytes)");
        byte[] token = Rfc3161.tokenFromReply(req, body);
        // Don't store a token that won't verify. Trust is the verifier's decision.
        Rfc3161.TokenCheck check = Rfc3161.verify(token, imprint, Optional.empty());
        if ( !check.valid() )
            throw new TSPException(String.join("; ", check.problems()));
        return token;
    }

    @Override
    public String toString() {
        return "TimestampAuthorities" + authorities + " policy=" + policy + " timeout=" + timeout.toMillis() + "ms";
    }

    /** For tests. */
    static void resetForTesting() {
        byConfig.clear();
    }
}

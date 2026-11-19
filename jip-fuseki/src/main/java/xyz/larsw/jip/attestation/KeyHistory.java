package xyz.larsw.jip.attestation;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

import org.apache.jena.atlas.json.JSON;
import org.apache.jena.atlas.json.JsonArray;
import org.apache.jena.atlas.json.JsonObject;

/**
 * The server's signing keys as a JWK Set (RFC 7517 section 5), for {@code GET /$/provenance/keys}.
 * <p>
 * The set holds the current signing key and every key the attestation store records as used
 * before it ({@link AttestationStore#keyActivations()}), so that attestations signed before a key
 * rollover can still be checked against a trusted key. Each JWK carries the standard members
 * ({@code kty}, {@code crv}, {@code x}, {@code y}; {@code kid}, the {@code did:key} verification
 * method that attestations name; {@code alg}; {@code use: "sig"}) and these additional ones:
 * {@code did} (the {@code did:key}), {@code status} ({@code "current"} or {@code "retired"}),
 * {@code activated} (the latest activation) and, for a retired key, {@code retired} (when the next
 * key was activated). The current key comes first, then the retired keys, most recent first.
 */
public final class KeyHistory {
    private KeyHistory() {}

    /** Media type of a JWK Set (RFC 7517 section 8.5.1). */
    public static final String MEDIA_TYPE = "application/jwk-set+json";

    /** The key last recorded per store, so that each attestation doesn't write to the store. */
    private static final ConcurrentHashMap<AttestationStore, String> recorded = new ConcurrentHashMap<>();

    /**
     * Record the signer's key as activated in the store, once per store and key in this process
     * (the store itself ignores a key that already is the latest activation).
     */
    public static void recordActivation(AttestationStore store, ProvenanceSigner signer) {
        String did = signer.didKey();
        if ( did.equals(recorded.get(store)) )
            return;
        store.recordKeyActivation(did, Instant.now());
        recorded.put(store, did);
    }

    /**
     * The JWK Set for the current key {@code currentDidKey} and the recorded activations
     * (which may or may not include the current key).
     */
    public static JsonObject jwkSet(String currentDidKey, Map<String, List<Instant>> activations) {
        Map<String, List<Instant>> all = new LinkedHashMap<>(activations);
        all.putIfAbsent(currentDidKey, List.of());
        record Entry(String did, Instant activated, Instant retired, boolean current) {}
        List<Entry> entries = new ArrayList<>();
        for ( Map.Entry<String, List<Instant>> e : all.entrySet() ) {
            Instant last = e.getValue().isEmpty() ? null : e.getValue().get(e.getValue().size() - 1);
            boolean current = e.getKey().equals(currentDidKey);
            Instant retired = current || last == null ? null : nextActivationAfter(last, e.getKey(), all).orElse(null);
            entries.add(new Entry(e.getKey(), last, retired, current));
        }
        entries.sort(Comparator.comparing(Entry::current).reversed()
                               .thenComparing(Entry::activated, Comparator.nullsLast(Comparator.reverseOrder())));
        JsonArray keys = new JsonArray();
        for ( Entry e : entries ) {
            DidKey.Key key = DidKey.resolve(e.did());
            JsonObject jwk = JSON.parse(KeyFormats.jwk(key.publicKey()));
            jwk.put("kid", DidKey.verificationMethod(key.publicKey()));
            jwk.put("alg", key.type().jwsAlgorithm());
            jwk.put("use", "sig");
            jwk.put("did", e.did());
            jwk.put("status", e.current() ? "current" : "retired");
            if ( e.activated() != null )
                jwk.put("activated", e.activated().toString());
            if ( e.retired() != null )
                jwk.put("retired", e.retired().toString());
            keys.add(jwk);
        }
        JsonObject set = new JsonObject();
        set.put("keys", keys);
        return set;
    }

    /** The earliest activation of another key after {@code after}. */
    private static Optional<Instant> nextActivationAfter(Instant after, String did, Map<String, List<Instant>> all) {
        return all.entrySet().stream()
                .filter(e -> !e.getKey().equals(did))
                .flatMap(e -> e.getValue().stream())
                .filter(t -> t.isAfter(after))
                .min(Comparator.naturalOrder());
    }
}

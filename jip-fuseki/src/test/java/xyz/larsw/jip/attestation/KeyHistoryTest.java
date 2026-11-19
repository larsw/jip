package xyz.larsw.jip.attestation;

import static org.junit.jupiter.api.Assertions.*;

import java.security.KeyPairGenerator;
import java.security.spec.ECGenParameterSpec;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.apache.jena.atlas.json.JsonArray;
import org.apache.jena.atlas.json.JsonObject;
import org.apache.jena.tdb2.DatabaseMgr;
import org.junit.jupiter.api.Test;

/** Key rollover: the key history in the attestation store, and the JWK Set made from it. */
class KeyHistoryTest {

    static String ecDid(String curve) throws Exception {
        KeyPairGenerator g = KeyPairGenerator.getInstance("EC");
        g.initialize(new ECGenParameterSpec(curve));
        return DidKey.didKey(g.generateKeyPair().getPublic());
    }

    static JsonObject key(JsonObject set, String did) {
        for ( var v : (JsonArray)set.get("keys") )
            if ( v.getAsObject().get("did").getAsString().value().equals(did) )
                return v.getAsObject();
        throw new AssertionError("no key " + did);
    }

    static String str(JsonObject o, String member) {
        return o.hasKey(member) ? o.get(member).getAsString().value() : null;
    }

    @Test
    void rolloverAndRollbackAreRecorded() throws Exception {
        AttestationStore store = AttestationStore.over(DatabaseMgr.createDatasetGraph());
        String a = ecDid("secp256r1");
        String b = ecDid("secp384r1");
        Instant t1 = Instant.parse("2026-11-01T00:00:00Z"), t2 = Instant.parse("2026-11-02T00:00:00Z"),
                t3 = Instant.parse("2026-11-03T00:00:00Z");
        assertTrue(store.recordKeyActivation(a, t1));
        assertFalse(store.recordKeyActivation(a, t2), "already the latest key");
        assertTrue(store.recordKeyActivation(b, t2), "rollover to b");
        assertEquals(Map.of(a, List.of(t1), b, List.of(t2)), store.keyActivations());

        JsonObject set = KeyHistory.jwkSet(b, store.keyActivations());
        JsonArray keys = (JsonArray)set.get("keys");
        assertEquals(2, keys.size());
        assertEquals(b, str(keys.get(0).getAsObject(), "did"), "current key first");
        JsonObject kb = key(set, b), ka = key(set, a);
        assertEquals("current", str(kb, "status"));
        assertEquals(t2.toString(), str(kb, "activated"));
        assertNull(str(kb, "retired"));
        assertEquals("ES384", str(kb, "alg"));
        assertEquals("retired", str(ka, "status"));
        assertEquals(t2.toString(), str(ka, "retired"), "retired when b was activated");
        assertEquals("ES256", str(ka, "alg"));
        assertEquals(DidKey.verificationMethod(DidKey.resolve(a).publicKey()), str(ka, "kid"));
        assertEquals("sig", str(ka, "use"));

        assertTrue(store.recordKeyActivation(a, t3), "rollback to a");
        JsonObject again = KeyHistory.jwkSet(a, store.keyActivations());
        assertEquals("current", str(key(again, a), "status"));
        assertEquals(t3.toString(), str(key(again, a), "activated"));
        assertEquals(t3.toString(), str(key(again, b), "retired"));
    }

    @Test
    void jwkSetRoundTripsThroughTheVerifier() throws Exception {
        String p256 = ecDid("secp256r1");
        String p384 = ecDid("secp384r1");
        SigningKey ed = SigningKey.generate();
        JsonObject set = KeyHistory.jwkSet(ed.didKey(), Map.of(p256, List.of(Instant.EPOCH), p384, List.of(Instant.EPOCH.plusSeconds(1))));
        assertEquals("EdDSA", str(key(set, ed.didKey()), "alg"));
        assertEquals(Set.of(p256, p384, ed.didKey()), TrustedKeys.fromJwkSet(set.toString()));
    }

    @Test
    void theKidIsNotTrustedOnlyTheKeyMaterial() throws Exception {
        String real = ecDid("secp256r1");
        String other = ecDid("secp256r1");
        JsonObject set = KeyHistory.jwkSet(real, Map.of());
        key(set, real).put("kid", DidKey.verificationMethod(DidKey.resolve(other).publicKey()));
        assertEquals(Set.of(real), TrustedKeys.fromJwkSet(set.toString()));
        assertThrows(IllegalArgumentException.class, () -> TrustedKeys.fromJwkSet("{\"keys\":[]}"));
        assertThrows(IllegalArgumentException.class, () -> TrustedKeys.fromJwkSet("{\"nokeys\":1}"));
    }
}

package xyz.larsw.jip.attestation;

import static org.junit.jupiter.api.Assertions.*;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.time.Instant;
import java.util.HexFormat;
import java.util.Base64;

import org.apache.jena.graph.Graph;
import org.apache.jena.graph.GraphMemFactory;
import org.apache.jena.graph.Node;
import org.apache.jena.graph.NodeFactory;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * The signing key, checked against the W3C vc-di-eddsa test vectors. The values are copied
 * from the verifier module's src/test/resources/w3c/vc-di-eddsa (keyPair.json,
 * combinedHashDataInt.txt, sigBTC58DataInt.txt), where the canonicalization and proof
 * construction are tested.
 */
class SigningKeyTest {

    private static final String PUBLIC_KEY_MULTIBASE = "z6MkrJVnaZkeFzdQyMZu1cgjg7k1pZZ6pvBQ7XJPt4swbTQ2";
    private static final String PRIVATE_KEY_MULTIBASE = "z3u2en7t5LR2WtQH5PfFqMqwVHBeXouLzo6haApm8XHqvjxq";
    private static final String VM = "did:key:" + PUBLIC_KEY_MULTIBASE + "#" + PUBLIC_KEY_MULTIBASE;
    private static final String COMBINED_HASH_DATA =
            "bea7b7acfbad0126b135104024a5f1733e705108f42d59668b05c0c50004c6b0"
            + "517744132ae165a5349155bef0bb0cf2258fff99dfe1dbd914b938d775a36017";
    private static final String SIGNATURE_BASE58 =
            "z2YwC8z3ap7yx1nZYCg4L3j3ApHsF8kgPdSb5xoS1VR7vPG3F561B52hYnQF9iseabecm3ijx4K1FBTQsCZahKZme";

    @TempDir
    Path tmp;

    static SigningKey vectorKey() {
        return SigningKey.fromPrivateKeyMultibase(PRIVATE_KEY_MULTIBASE);
    }

    @Test
    void keyAndIdentifiers() {
        SigningKey key = vectorKey();
        assertEquals(PUBLIC_KEY_MULTIBASE, key.publicKeyMultibase(), "public key derived from seed");
        assertEquals("did:key:" + PUBLIC_KEY_MULTIBASE, key.didKey());
        assertEquals(VM, key.verificationMethod());
        assertArrayEquals(key.rawPublicKey(), DidKey.publicKey(key.didKey()));
        assertArrayEquals(key.rawPublicKey(), DidKey.publicKey(VM));
    }

    @Test
    void signatureMatchesVector() {
        byte[] hashData = HexFormat.of().parseHex(COMBINED_HASH_DATA);
        byte[] sig = vectorKey().sign(hashData);   // Ed25519 is deterministic
        assertEquals(SIGNATURE_BASE58, Base58.encodeMultibase(sig));
        assertTrue(DidKey.verify(DidKey.publicKey(VM), hashData, sig));
    }

    @Test
    void signedGraphVerifies() {
        SigningKey key = SigningKey.generate();
        Node doc = NodeFactory.createURI("urn:example:doc");
        Graph g = GraphMemFactory.createDefaultGraph();
        g.add(doc, NodeFactory.createURI("https://schema.org/name"), NodeFactory.createLiteralString("Example"));
        DataIntegrityProof.sign(g, doc, key, Instant.parse("2026-01-01T00:00:00Z"));
        DataIntegrityProof.Verification v = DataIntegrityProof.verify(g, doc);
        assertTrue(v.valid(), () -> v.problems().toString());
        assertEquals(key.verificationMethod(), v.verificationMethod());
    }

    @Test
    void keyPemRoundTripAndPersistence() {
        Path pem = tmp.resolve("keys/signing-key.pem");
        SigningKey generated = SigningKey.loadOrGenerate(pem);
        SigningKey loaded = SigningKey.loadOrGenerate(pem);
        assertEquals(generated.didKey(), loaded.didKey(), "generated once, then loaded");
        assertEquals(generated.didKey(), SigningKey.fromPem(generated.toPem()).didKey());
        assertTrue(generated.jwk().contains("\"crv\":\"Ed25519\""));
        try {
            assertEquals("rw-------", PosixFilePermissions.toString(Files.getPosixFilePermissions(pem)));
        } catch (IOException | UnsupportedOperationException ignored) {}
    }

    /** Written by {@code openssl genpkey -algorithm ed25519} (a throwaway test key). */
    private static final String OPENSSL_PEM = """
            -----BEGIN PRIVATE KEY-----
            MC4CAQAwBQYDK2VwBCIEIBTa8HmB4reLI0EfDeeWYaUlRWQRumhNqjCmy8Kt17y0
            -----END PRIVATE KEY-----
            """;
    /** Its public key, from {@code openssl pkey -pubout}. */
    private static final String OPENSSL_PUBLIC_HEX = "877e7cff47026655552a64dba32eb02ce8ef3c620142f11c07c35796fc4c3b16";

    @Test
    void readsKeysWrittenByOpenSslAndTheJdk() throws Exception {
        assertEquals(OPENSSL_PUBLIC_HEX, HexFormat.of().formatHex(SigningKey.fromPem(OPENSSL_PEM).rawPublicKey()));

        java.security.KeyPair jdk = java.security.KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
        String pem = "-----BEGIN PRIVATE KEY-----\n" + Base64.getMimeEncoder().encodeToString(jdk.getPrivate().getEncoded())
                     + "\n-----END PRIVATE KEY-----\n";
        assertArrayEquals(DidKey.fromSpki(jdk.getPublic().getEncoded()), SigningKey.fromPem(pem).rawPublicKey());
        // What toPem writes, the JDK reads.
        String written = SigningKey.generate().toPem();
        String block = written.substring(0, written.indexOf("-----BEGIN PUBLIC KEY-----"))
                .replaceAll("-----[A-Z ]+-----", "").replaceAll("\\s", "");
        assertNotNull(java.security.KeyFactory.getInstance("Ed25519")
                .generatePrivate(new java.security.spec.PKCS8EncodedKeySpec(Base64.getDecoder().decode(block))));
    }

    @Test
    void otherKeyTypesAreRejected() throws Exception {
        java.security.KeyPair ec = java.security.KeyPairGenerator.getInstance("EC").generateKeyPair();
        String pem = "-----BEGIN PRIVATE KEY-----\n" + Base64.getMimeEncoder().encodeToString(ec.getPrivate().getEncoded())
                     + "\n-----END PRIVATE KEY-----\n";
        IllegalArgumentException ex = assertThrows(IllegalArgumentException.class, () -> SigningKey.fromPem(pem));
        assertTrue(ex.getMessage().startsWith("Not an Ed25519"), ex.getMessage());
        assertThrows(IllegalArgumentException.class, () -> SigningKey.fromPem("no pem here"));
        assertThrows(IllegalArgumentException.class, () -> DidKey.fromSpki(ec.getPublic().getEncoded()));
    }

    @Test
    void pemWithMismatchedPublicKeyIsRejected() {
        String privatePart = SigningKey.generate().toPem();
        privatePart = privatePart.substring(0, privatePart.indexOf("-----BEGIN PUBLIC KEY-----"));
        String mixed = privatePart + SigningKey.generate().publicPem();
        assertThrows(IllegalArgumentException.class, () -> SigningKey.fromPem(mixed));
    }
}

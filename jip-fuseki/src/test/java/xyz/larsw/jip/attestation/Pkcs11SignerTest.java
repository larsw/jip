package xyz.larsw.jip.attestation;

import static org.junit.jupiter.api.Assertions.*;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Stream;

import org.apache.jena.graph.Graph;
import org.apache.jena.graph.GraphMemFactory;
import org.apache.jena.graph.Node;
import org.apache.jena.graph.NodeFactory;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIf;

/**
 * The PKCS#11 signer against a real SoftHSM2 token. Runs where SoftHSM2 is installed (the Docker
 * build installs it): {@code SOFTHSM2_CONF} (set by Surefire) points into target/, and the token
 * is initialized with {@code softhsm2-util}. {@code JIP_TEST_PKCS11_LIBRARY} overrides the
 * library path.
 */
@EnabledIf("softHsmAvailable")
class Pkcs11SignerTest {

    static final String PIN = "1234";
    static final List<String> LIBRARIES = List.of(
            "/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so", "/usr/lib/aarch64-linux-gnu/softhsm/libsofthsm2.so",
            "/usr/lib/softhsm/libsofthsm2.so", "/usr/local/lib/softhsm/libsofthsm2.so", "/opt/homebrew/lib/softhsm/libsofthsm2.so");

    static Optional<Path> library() {
        String env = System.getenv("JIP_TEST_PKCS11_LIBRARY");
        if ( env != null && !env.isBlank() )
            return Optional.of(Path.of(env)).filter(Files::exists);
        return LIBRARIES.stream().map(Path::of).filter(Files::exists).findFirst();
    }

    static boolean softHsmAvailable() {
        if ( System.getenv("SOFTHSM2_CONF") == null || library().isEmpty() )
            return false;
        try {
            return new ProcessBuilder("softhsm2-util", "--version").redirectErrorStream(true).start().waitFor() == 0;
        } catch (IOException | InterruptedException ex) {
            return false;
        }
    }

    @BeforeAll
    static void initToken() throws Exception {
        Path conf = Path.of(System.getenv("SOFTHSM2_CONF"));
        Path dir = conf.getParent();
        if ( Files.exists(dir) ) {
            try ( Stream<Path> files = Files.walk(dir) ) {
                files.sorted(Comparator.reverseOrder()).forEach(p -> p.toFile().delete());
            }
        }
        Files.createDirectories(dir.resolve("tokens"));
        Files.writeString(conf, "directories.tokendir = " + dir.resolve("tokens") + "\nobjectstore.backend = file\n");
        Process p = new ProcessBuilder("softhsm2-util", "--init-token", "--free", "--label", "jip-test", "--pin", PIN, "--so-pin", "5678")
                .redirectErrorStream(true).start();
        String out = new String(p.getInputStream().readAllBytes());
        assertEquals(0, p.waitFor(), out);
    }

    static SignerSettings settings(String... extra) {
        Map<String, String> m = new HashMap<>();
        m.put(Pkcs11Signer.ENV_LIBRARY, library().orElseThrow().toString());
        m.put(Pkcs11Signer.ENV_PIN, PIN);
        for ( int i = 0 ; i + 1 < extra.length ; i += 2 )
            m.put(extra[i], extra[i + 1]);
        return SignerSettings.of(m);
    }

    static void assertSignsVerifiably(ProvenanceSigner signer) {
        Node doc = NodeFactory.createURI("urn:example:doc");
        Graph g = GraphMemFactory.createDefaultGraph();
        g.add(doc, NodeFactory.createURI("https://schema.org/name"), NodeFactory.createLiteralString("Example"));
        DataIntegrityProof.sign(g, doc, signer, Instant.now());
        DataIntegrityProof.Verification v = DataIntegrityProof.verify(g, doc);
        assertTrue(v.valid(), () -> v.problems().toString());
        assertEquals(signer.verificationMethod(), v.verificationMethod());
    }

    @Test
    void generatesAP256KeyOnTheTokenAndSigns() {
        ProvenanceSigner first = ProvenanceKeys.open(settings(Pkcs11Signer.ENV_KEY, "p256", Pkcs11Signer.ENV_GENERATE, "P-256"));
        assertEquals("pkcs11", first.kind());
        assertEquals(KeyType.P256, first.keyType());
        assertTrue(first.didKey().startsWith("did:key:zDn"), first.didKey());
        assertSignsVerifiably(first);

        // The key is a token object: a new connection finds it without generating.
        ProvenanceSigner again = ProvenanceKeys.open(settings(Pkcs11Signer.ENV_KEY, "p256"));
        assertEquals(first.didKey(), again.didKey());
        assertSignsVerifiably(again);
    }

    @Test
    void generatesAP384KeyOnTheTokenAndSigns() {
        ProvenanceSigner s = ProvenanceKeys.open(settings(Pkcs11Signer.ENV_KEY, "p384", Pkcs11Signer.ENV_GENERATE, "P-384"));
        assertEquals(KeyType.P384, s.keyType());
        assertTrue(s.didKey().startsWith("did:key:z82"), s.didKey());
        assertSignsVerifiably(s);
    }

    @Test
    void missingKeyIsAnErrorUnlessGenerationIsAllowed() {
        IllegalStateException ex = assertThrows(IllegalStateException.class,
                () -> ProvenanceKeys.open(settings(Pkcs11Signer.ENV_KEY, "absent")));
        assertTrue(ex.getMessage().contains("No key 'absent'"), ex.getMessage());
        assertTrue(ex.getMessage().contains(Pkcs11Signer.ENV_GENERATE), ex.getMessage());
    }

    @Test
    void attestationsSignedOnTheTokenVerify() {
        ProvenanceSigner s = ProvenanceKeys.open(settings(Pkcs11Signer.ENV_KEY, "attest", Pkcs11Signer.ENV_GENERATE, "P-256"));
        java.util.UUID id = java.util.UUID.randomUUID();
        AttestationBuilder.Input in = new AttestationBuilder.Input(id, java.util.UUID.randomUUID(), null, 7, List.of("x"), false, 0,
                xyz.larsw.jip.canon.ResultSetEncoding.digest(List.of("x"), List.of(), false), "SELECT ?x {}", null, Instant.now(), Instant.now());
        Graph attestation = AttestationBuilder.buildSigned(in, s, "test");
        AttestationVerifier.Report r = AttestationVerifier.verify(attestation, List.of("x"), List.of(), Optional.of(s.didKey()));
        assertTrue(r.valid(), () -> r.problems().toString());
        assertTrue(r.verificationMethod().startsWith("did:key:zDn"));
    }
}

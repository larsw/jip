package org.example.jena.provenance.cert;

import static org.junit.jupiter.api.Assertions.*;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.HexFormat;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.apache.jena.graph.Graph;
import org.apache.jena.graph.GraphMemFactory;
import org.apache.jena.graph.Node;
import org.apache.jena.graph.NodeFactory;
import org.apache.jena.riot.Lang;
import org.apache.jena.riot.RDFParser;
import org.example.jena.provenance.canon.RdfCanonicalizer;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * eddsa-rdfc-2022 against the W3C vc-di-eddsa test vectors
 * (src/test/resources/w3c/vc-di-eddsa, see SOURCE).
 */
class DataIntegrityProofTest {

    private static final String DIR = "/w3c/vc-di-eddsa/";
    private static final String VM =
            "did:key:z6MkrJVnaZkeFzdQyMZu1cgjg7k1pZZ6pvBQ7XJPt4swbTQ2#z6MkrJVnaZkeFzdQyMZu1cgjg7k1pZZ6pvBQ7XJPt4swbTQ2";
    private static final Instant CREATED = Instant.parse("2023-02-24T23:36:38Z");
    private static final Node DOC = NodeFactory.createURI("urn:uuid:58172aac-d8ba-11ed-83dd-0b3aef56cc33");

    @TempDir
    Path tmp;

    static SigningKey vectorKey() throws IOException {
        String json = read("keyPair.json");
        SigningKey key = SigningKey.fromPrivateKeyMultibase(jsonValue(json, "privateKeyMultibase"));
        assertEquals(jsonValue(json, "publicKeyMultibase"), key.publicKeyMultibase(), "public key derived from seed");
        return key;
    }

    @Test
    void keyAndIdentifiers() throws IOException {
        SigningKey key = vectorKey();
        assertEquals(VM, key.verificationMethod());
        assertArrayEquals(key.rawPublicKey(), SigningKey.publicKeyFromDidKey(key.didKey()));
        assertArrayEquals(key.rawPublicKey(), SigningKey.publicKeyFromDidKey(VM));
    }

    @Test
    void hashesMatchVectors() throws IOException {
        assertEquals(read("docHashDataInt.txt").strip(), RdfCanonicalizer.sha256Hex(read("canonDocDataInt.txt")));
        assertEquals(read("proofHashDataInt.txt").strip(), RdfCanonicalizer.sha256Hex(read("proofCanonDataInt.txt")));
    }

    @Test
    void proofConfigCanonicalFormMatchesVector() throws IOException {
        // Our RDF construction of the proof options must equal the JSON-LD expansion used by the spec.
        Graph config = DataIntegrityProof.proofConfig(NodeFactory.createBlankNode(), VM, CREATED);
        assertEquals(read("proofCanonDataInt.txt"), RdfCanonicalizer.standard().canonicalize(config));
    }

    @Test
    void signatureMatchesVector() throws IOException {
        SigningKey key = vectorKey();
        Graph doc = parse(read("canonDocDataInt.txt"));
        assertEquals(read("canonDocDataInt.txt"), RdfCanonicalizer.standard().canonicalize(doc));

        Graph config = DataIntegrityProof.proofConfig(NodeFactory.createBlankNode(), VM, CREATED);
        byte[] hashData = DataIntegrityProof.hashData(config, doc);
        assertEquals(read("combinedHashDataInt.txt").strip(), HexFormat.of().formatHex(hashData));

        byte[] sig = key.sign(hashData);   // Ed25519 is deterministic
        assertEquals(read("sigHexDataInt.txt").strip(), HexFormat.of().formatHex(sig));
        assertEquals(read("sigBTC58DataInt.txt").strip(), Base58.encodeMultibase(sig));

        // End to end: sign the document graph, check proofValue and verify.
        Node proof = DataIntegrityProof.sign(doc, DOC, key, CREATED);
        String proofValue = doc.find(proof, Vocab.secProofValue, Node.ANY).next().getObject().getLiteralLexicalForm();
        assertEquals(read("sigBTC58DataInt.txt").strip(), proofValue);
        assertTrue(DataIntegrityProof.verify(doc, DOC).valid());
    }

    @Test
    void tamperingIsDetected() throws IOException {
        SigningKey key = vectorKey();
        Graph doc = parse(read("canonDocDataInt.txt"));
        DataIntegrityProof.sign(doc, DOC, key, CREATED);
        doc.add(DOC, NodeFactory.createURI("https://schema.org/name"), NodeFactory.createLiteralString("Forged"));
        DataIntegrityProof.Verification v = DataIntegrityProof.verify(doc, DOC);
        assertFalse(v.valid());
        assertEquals(VM, v.verificationMethod());
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
            assertEquals("rw-------", java.nio.file.attribute.PosixFilePermissions.toString(Files.getPosixFilePermissions(pem)));
        } catch (IOException | UnsupportedOperationException ignored) {}
    }

    @Test
    void base58RoundTripWithLeadingZeros() {
        byte[] data = { 0, 0, 1, 2, 3, (byte)0xff };
        assertArrayEquals(data, Base58.decode(Base58.encode(data)));
        assertEquals("11", Base58.encode(new byte[] { 0, 0 }));
        assertArrayEquals(new byte[0], Base58.decode(""));
    }

    static Graph parse(String nquads) {
        Graph g = GraphMemFactory.createDefaultGraph();
        RDFParser.fromString(nquads, Lang.NTRIPLES).parse(g);
        return g;
    }

    static String read(String file) throws IOException {
        try ( InputStream in = DataIntegrityProofTest.class.getResourceAsStream(DIR + file) ) {
            assertNotNull(in, "missing " + file);
            return new String(in.readAllBytes(), StandardCharsets.UTF_8);
        }
    }

    static String jsonValue(String json, String key) {
        Matcher m = Pattern.compile("\"" + key + "\"\\s*:\\s*\"([^\"]+)\"").matcher(json);
        assertTrue(m.find(), key);
        return m.group(1);
    }
}

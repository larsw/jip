package xyz.larsw.jip.attestation;

import static org.junit.jupiter.api.Assertions.*;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
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
import xyz.larsw.jip.canon.RdfCanonicalizer;
import org.junit.jupiter.api.Test;

/**
 * eddsa-rdfc-2022 against the W3C vc-di-eddsa test vectors
 * (src/test/resources/w3c/vc-di-eddsa, see SOURCE).
 * <p>
 * The library has no private key, so signing is checked with a {@link ProofSigner} that
 * returns the vector's signature for the vector's hash data. Signing with a real key is
 * tested by {@code SigningKeyTest} in the Fuseki module.
 */
class DataIntegrityProofTest {

    private static final String DIR = "/w3c/vc-di-eddsa/";
    private static final String VM =
            "did:key:z6MkrJVnaZkeFzdQyMZu1cgjg7k1pZZ6pvBQ7XJPt4swbTQ2#z6MkrJVnaZkeFzdQyMZu1cgjg7k1pZZ6pvBQ7XJPt4swbTQ2";
    private static final Instant CREATED = Instant.parse("2023-02-24T23:36:38Z");
    private static final Node DOC = NodeFactory.createURI("urn:uuid:58172aac-d8ba-11ed-83dd-0b3aef56cc33");

    @Test
    void didKeyIdentifiers() throws IOException {
        String publicKeyMultibase = jsonValue(read("keyPair.json"), "publicKeyMultibase");
        byte[] raw = DidKey.publicKey(VM);
        assertEquals(32, raw.length);
        assertArrayEquals(raw, DidKey.publicKey("did:key:" + publicKeyMultibase));
        assertEquals(publicKeyMultibase, DidKey.publicKeyMultibase(raw));
        assertEquals("did:key:" + publicKeyMultibase, DidKey.didKey(raw));
        assertEquals(VM, DidKey.verificationMethod(raw));
        assertArrayEquals(raw, DidKey.fromSpki(DidKey.toSpki(raw)));
        assertThrows(IllegalArgumentException.class, () -> DidKey.publicKey("did:web:example.org"));
        assertThrows(IllegalArgumentException.class, () -> DidKey.publicKey(VM.substring(0, VM.indexOf('#') + 1) + "z6Mkother"));
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
    void hashDataMatchesVector() throws IOException {
        Graph doc = parse(read("canonDocDataInt.txt"));
        assertEquals(read("canonDocDataInt.txt"), RdfCanonicalizer.standard().canonicalize(doc));
        Graph config = DataIntegrityProof.proofConfig(NodeFactory.createBlankNode(), VM, CREATED);
        assertEquals(read("combinedHashDataInt.txt").strip(), HexFormat.of().formatHex(DataIntegrityProof.hashData(config, doc)));
    }

    @Test
    void vectorSignatureVerifies() throws IOException {
        byte[] hashData = HexFormat.of().parseHex(read("combinedHashDataInt.txt").strip());
        byte[] sig = HexFormat.of().parseHex(read("sigHexDataInt.txt").strip());
        assertEquals(read("sigBTC58DataInt.txt").strip(), Base58.encodeMultibase(sig));
        assertTrue(DidKey.verify(DidKey.publicKey(VM), hashData, sig));
        hashData[0] ^= 1;
        assertFalse(DidKey.verify(DidKey.publicKey(VM), hashData, sig));
    }

    @Test
    void signAndVerifyWithVectorSignature() throws IOException {
        Graph doc = parse(read("canonDocDataInt.txt"));
        Node proof = DataIntegrityProof.sign(doc, DOC, vectorSigner(), CREATED);
        String proofValue = doc.find(proof, Vocab.secProofValue, Node.ANY).next().getObject().getLiteralLexicalForm();
        assertEquals(read("sigBTC58DataInt.txt").strip(), proofValue);

        DataIntegrityProof.Verification v = DataIntegrityProof.verify(doc, DOC);
        assertTrue(v.valid(), () -> v.problems().toString());
        assertEquals(VM, v.verificationMethod());
        assertEquals(CREATED, v.created());
    }

    @Test
    void tamperingIsDetected() throws IOException {
        Graph doc = parse(read("canonDocDataInt.txt"));
        DataIntegrityProof.sign(doc, DOC, vectorSigner(), CREATED);
        doc.add(DOC, NodeFactory.createURI("https://schema.org/name"), NodeFactory.createLiteralString("Forged"));
        DataIntegrityProof.Verification v = DataIntegrityProof.verify(doc, DOC);
        assertFalse(v.valid());
        assertEquals(VM, v.verificationMethod());
    }

    /** Signs only the vector's hash data, with the vector's (deterministic Ed25519) signature. */
    static ProofSigner vectorSigner() throws IOException {
        String expectedHashData = read("combinedHashDataInt.txt").strip();
        byte[] sig = HexFormat.of().parseHex(read("sigHexDataInt.txt").strip());
        return new ProofSigner() {
            @Override
            public String verificationMethod() {
                return VM;
            }

            @Override
            public byte[] sign(byte[] data) {
                assertEquals(expectedHashData, HexFormat.of().formatHex(data), "hash data to sign");
                return sig.clone();
            }
        };
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

package xyz.larsw.jip.attestation;

import static org.junit.jupiter.api.Assertions.*;

import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.AlgorithmParameters;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPrivateKeySpec;
import java.time.Instant;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.apache.jena.graph.Graph;
import org.apache.jena.graph.GraphMemFactory;
import org.apache.jena.graph.Node;
import org.apache.jena.graph.NodeFactory;
import org.apache.jena.riot.Lang;
import org.apache.jena.riot.RDFParser;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import xyz.larsw.jip.canon.RdfCanonicalizer;

/**
 * ecdsa-rdfc-2019 with P-256 and P-384 against the W3C vc-di-ecdsa test vectors
 * (src/test/resources/w3c/vc-di-ecdsa, see SOURCE).
 * <p>
 * ECDSA signatures are randomized, so the vector's signature is checked by verifying it, and
 * signing is checked by a round trip with the vector's secret key.
 */
class EcdsaDataIntegrityProofTest {

    private static final Instant CREATED = Instant.parse("2023-02-24T23:36:38Z");
    private static final Node DOC = NodeFactory.createURI("urn:uuid:58172aac-d8ba-11ed-83dd-0b3aef56cc33");

    enum Curve {
        P256(KeyType.P256, "p256", 0x1306),
        P384(KeyType.P384, "p384", 0x1307);

        final KeyType type;
        final String dir;
        final int privateMulticodec;

        Curve(KeyType type, String dir, int privateMulticodec) {
            this.type = type;
            this.dir = dir;
            this.privateMulticodec = privateMulticodec;
        }

        String read(String file) throws IOException {
            try ( InputStream in = EcdsaDataIntegrityProofTest.class.getResourceAsStream("/w3c/vc-di-ecdsa/" + dir + "/" + file) ) {
                assertNotNull(in, "missing " + dir + "/" + file);
                return new String(in.readAllBytes(), StandardCharsets.UTF_8);
            }
        }

        String publicKeyMultibase() throws IOException {
            return jsonValue(read("keyPair.json"), "publicKeyMultibase");
        }

        String vm() throws IOException {
            String mb = publicKeyMultibase();
            return "did:key:" + mb + "#" + mb;
        }

        /** The vector's private key: multicodec p256-priv / p384-priv + big-endian scalar. */
        PrivateKey privateKey() throws Exception {
            byte[] bytes = Base58.decodeMultibase(jsonValue(read("keyPair.json"), "secretKeyMultibase"));
            int varint = (bytes[0] & 0x7f) | ((bytes[1] & 0x7f) << 7);
            assertEquals(privateMulticodec, varint, "private key multicodec");
            AlgorithmParameters params = AlgorithmParameters.getInstance("EC");
            params.init(new ECGenParameterSpec(type.jcaCurve()));
            BigInteger s = new BigInteger(1, Arrays.copyOfRange(bytes, 2, bytes.length));
            return KeyFactory.getInstance("EC").generatePrivate(new ECPrivateKeySpec(s, params.getParameterSpec(ECParameterSpec.class)));
        }
    }

    @ParameterizedTest
    @EnumSource(Curve.class)
    void didKeyResolvesAndRoundTrips(Curve c) throws IOException {
        DidKey.Key key = DidKey.resolve(c.vm());
        assertEquals(c.type, key.type());
        assertEquals(c.type, DidKey.keyType(key.publicKey()));
        assertEquals(c.publicKeyMultibase(), DidKey.publicKeyMultibase(key.publicKey()));
        assertEquals(c.vm(), DidKey.verificationMethod(key.publicKey()));
        assertTrue(c.publicKeyMultibase().startsWith(c == Curve.P256 ? "zDn" : "z82"));
        // The Ed25519-only API refuses EC keys.
        assertThrows(IllegalArgumentException.class, () -> DidKey.publicKey(c.vm()));
    }

    @ParameterizedTest
    @EnumSource(Curve.class)
    void hashesMatchVectors(Curve c) throws Exception {
        MessageDigest md = MessageDigest.getInstance(c.type.digest());
        assertEquals(c.read("docHash.txt").strip(), HexFormat.of().formatHex(md.digest(c.read("canonDoc.txt").getBytes(StandardCharsets.UTF_8))));
        assertEquals(c.read("proofHash.txt").strip(), HexFormat.of().formatHex(md.digest(c.read("proofCanon.txt").getBytes(StandardCharsets.UTF_8))));
    }

    @ParameterizedTest
    @EnumSource(Curve.class)
    void proofConfigAndHashDataMatchVectors(Curve c) throws IOException {
        Graph config = DataIntegrityProof.proofConfig(NodeFactory.createBlankNode(), KeyType.ECDSA_RDFC_2019, c.vm(), CREATED);
        assertEquals(c.read("proofCanon.txt"), RdfCanonicalizer.standard().canonicalize(config));
        Graph doc = parse(c.read("canonDoc.txt"));
        assertEquals(c.read("combinedHash.txt").strip(),
                     HexFormat.of().formatHex(DataIntegrityProof.hashData(config, doc, c.type.digest())));
    }

    @ParameterizedTest
    @EnumSource(Curve.class)
    void vectorSignatureVerifies(Curve c) throws IOException {
        byte[] hashData = HexFormat.of().parseHex(c.read("combinedHash.txt").strip());
        byte[] sig = HexFormat.of().parseHex(c.read("sigHex.txt").strip());
        assertEquals(c.read("sigBTC58.txt").strip(), Base58.encodeMultibase(sig));
        DidKey.Key key = DidKey.resolve(c.vm());
        assertTrue(DidKey.verify(key, hashData, sig));
        hashData[0] ^= 1;
        assertFalse(DidKey.verify(key, hashData, sig));
    }

    @ParameterizedTest
    @EnumSource(Curve.class)
    void vectorSignatureVerifiesAsAProof(Curve c) throws IOException {
        Graph doc = parse(c.read("canonDoc.txt"));
        String expectedHashData = c.read("combinedHash.txt").strip();
        byte[] sig = HexFormat.of().parseHex(c.read("sigHex.txt").strip());
        String vm = c.vm();
        DataIntegrityProof.sign(doc, DOC, new ProofSigner() {
            @Override
            public String verificationMethod() {
                return vm;
            }

            @Override
            public byte[] sign(byte[] data) {
                assertEquals(expectedHashData, HexFormat.of().formatHex(data), "hash data to sign");
                return sig.clone();
            }

            @Override
            public KeyType keyType() {
                return c.type;
            }
        }, CREATED);
        DataIntegrityProof.Verification v = DataIntegrityProof.verify(doc, DOC);
        assertTrue(v.valid(), () -> v.problems().toString());

        doc.add(DOC, NodeFactory.createURI("https://schema.org/name"), NodeFactory.createLiteralString("Forged"));
        assertFalse(DataIntegrityProof.verify(doc, DOC).valid());
    }

    @ParameterizedTest
    @EnumSource(Curve.class)
    void signsWithTheVectorKey(Curve c) throws Exception {
        PrivateKey priv = c.privateKey();
        String vm = c.vm();
        Graph doc = parse(c.read("canonDoc.txt"));
        DataIntegrityProof.sign(doc, DOC, ecdsaSigner(priv, vm, c.type), Instant.now());
        DataIntegrityProof.Verification v = DataIntegrityProof.verify(doc, DOC);
        assertTrue(v.valid(), () -> v.problems().toString());
        assertTrue(doc.contains(Node.ANY, Vocab.secCryptosuite,
                                NodeFactory.createLiteralDT(KeyType.ECDSA_RDFC_2019,
                                        org.apache.jena.datatypes.TypeMapper.getInstance().getSafeTypeByName(Vocab.secCryptosuiteString.getURI()))));
    }

    @ParameterizedTest
    @EnumSource(Curve.class)
    void cryptosuiteMustMatchTheKey(Curve c) throws Exception {
        // An ECDSA signature presented as eddsa-rdfc-2022 is refused.
        PrivateKey priv = c.privateKey();
        String vm = c.vm();
        Graph doc = parse(c.read("canonDoc.txt"));
        ProofSigner wrongSuite = new ProofSigner() {
            @Override
            public String verificationMethod() {
                return vm;
            }

            @Override
            public byte[] sign(byte[] data) {
                return ecdsaSigner(priv, vm, c.type).sign(data);
            }
        };
        DataIntegrityProof.sign(doc, DOC, wrongSuite, Instant.now());
        DataIntegrityProof.Verification v = DataIntegrityProof.verify(doc, DOC);
        assertFalse(v.valid());
        assertTrue(v.problems().get(0).contains("does not use"), v.problems().toString());
    }

    static ProofSigner ecdsaSigner(PrivateKey priv, String vm, KeyType type) {
        return new ProofSigner() {
            @Override
            public String verificationMethod() {
                return vm;
            }

            @Override
            public byte[] sign(byte[] data) {
                try {
                    Signature s = Signature.getInstance(type.signatureAlgorithm());
                    s.initSign(priv);
                    s.update(data);
                    return s.sign();
                } catch (Exception ex) {
                    throw new IllegalStateException(ex);
                }
            }

            @Override
            public KeyType keyType() {
                return type;
            }
        };
    }

    static Graph parse(String nquads) {
        Graph g = GraphMemFactory.createDefaultGraph();
        RDFParser.fromString(nquads, Lang.NTRIPLES).parse(g);
        return g;
    }

    static String jsonValue(String json, String key) {
        Matcher m = Pattern.compile("\"" + key + "\"\\s*:\\s*\"([^\"]+)\"").matcher(json);
        assertTrue(m.find(), key);
        return m.group(1);
    }
}

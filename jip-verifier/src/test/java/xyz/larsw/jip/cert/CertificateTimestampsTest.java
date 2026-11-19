package xyz.larsw.jip.cert;

import static org.junit.jupiter.api.Assertions.*;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.Optional;

import org.apache.jena.graph.Graph;
import org.apache.jena.graph.GraphMemFactory;
import org.apache.jena.graph.Node;
import org.apache.jena.graph.NodeFactory;
import org.apache.jena.vocabulary.RDFS;
import org.bouncycastle.tsp.TSPException;
import org.bouncycastle.tsp.TimeStampRequest;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

class CertificateTimestampsTest {

    static final Node DOC = NodeFactory.createURI("urn:uuid:7d0e0d5c-0000-4000-8000-000000000001");
    static TestTsa tsa;

    @BeforeAll
    static void setup() {
        tsa = new TestTsa();
    }

    /** A signer with a fresh Ed25519 key. */
    static ProofSigner signer() throws Exception {
        KeyPair kp = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
        String vm = DidKey.verificationMethod(DidKey.fromSpki(kp.getPublic().getEncoded()));
        return new ProofSigner() {
            @Override
            public String verificationMethod() {
                return vm;
            }

            @Override
            public byte[] sign(byte[] data) {
                try {
                    Signature s = Signature.getInstance("Ed25519");
                    s.initSign(kp.getPrivate());
                    s.update(data);
                    return s.sign();
                } catch (Exception ex) {
                    throw new IllegalStateException(ex);
                }
            }
        };
    }

    static Graph signedDocument(String label) throws Exception {
        Graph g = GraphMemFactory.createDefaultGraph();
        g.add(DOC, RDFS.label.asNode(), NodeFactory.createLiteralString(label));
        DataIntegrityProof.sign(g, DOC, signer(), Instant.now());
        return g;
    }

    static Graph stamped(TestTsa authority) throws Exception {
        Graph g = signedDocument("certified");
        byte[] token = authority.token(CertificateTimestamps.messageImprint(g, DOC));
        CertificateTimestamps.attach(g, DOC, token, "https://tsa.example/");
        return g;
    }

    @Test
    void timestampCoversTheSignatureAndLeavesTheProofIntact() throws Exception {
        Graph g = stamped(tsa);

        assertFalse(DataIntegrityProof.verify(g, DOC).valid(), "the timestamp is not part of the signed document");
        assertTrue(DataIntegrityProof.verify(CertificateTimestamps.withoutTimestamps(g, DOC), DOC).valid());

        List<CertificateTimestamps.Check> checks = CertificateTimestamps.verify(g, DOC, Optional.of(tsa.anchors()));
        assertEquals(1, checks.size());
        Rfc3161.TokenCheck c = checks.get(0).token();
        assertTrue(c.valid(), () -> c.problems().toString());
        assertEquals(Boolean.TRUE, c.trusted());
        assertTrue(c.acceptable());
        assertEquals("CN=jip test TSA", c.tsaName());
        assertEquals(TestTsa.POLICY.getId(), c.policy());
        assertEquals("https://tsa.example/", checks.get(0).authority());
        assertTrue(Duration.between(c.genTime(), Instant.now()).abs().toMinutes() < 5);
    }

    @Test
    void trustDependsOnTheAnchors() throws Exception {
        Graph g = stamped(tsa);
        Rfc3161.TokenCheck system = CertificateTimestamps.verify(g, DOC, Optional.of(Rfc3161.systemTrustAnchors())).get(0).token();
        assertTrue(system.valid());
        assertEquals(Boolean.FALSE, system.trusted(), "a private CA is not in the JVM trust store");
        assertFalse(system.acceptable());

        Rfc3161.TokenCheck unchecked = CertificateTimestamps.verify(g, DOC, Optional.empty()).get(0).token();
        assertNull(unchecked.trusted());
        assertTrue(unchecked.acceptable());

        Rfc3161.TokenCheck otherCa = CertificateTimestamps.verify(g, DOC, Optional.of(new TestTsa().anchors())).get(0).token();
        assertEquals(Boolean.FALSE, otherCa.trusted());
    }

    @Test
    void tokenForAnotherSignatureIsRejected() throws Exception {
        Graph g = signedDocument("one");
        Graph other = signedDocument("two");
        CertificateTimestamps.attach(g, DOC, tsa.token(CertificateTimestamps.messageImprint(other, DOC)), null);
        Rfc3161.TokenCheck c = CertificateTimestamps.verify(g, DOC, Optional.of(tsa.anchors())).get(0).token();
        assertFalse(c.imprintValid());
        assertFalse(c.valid());
    }

    @Test
    void corruptedTokenIsRejected() throws Exception {
        Graph g = signedDocument("certified");
        byte[] token = tsa.token(CertificateTimestamps.messageImprint(g, DOC));
        // Flip a byte near the end: inside the TSA's signature value.
        token[token.length - 10] ^= 0x01;
        Node t = NodeFactory.createBlankNode();
        g.add(DOC, Vocab.timestamp, t);
        g.add(t, Vocab.timestampToken, NodeFactory.createLiteralDT(java.util.Base64.getEncoder().encodeToString(token),
                                                                 org.apache.jena.datatypes.xsd.XSDDatatype.XSDbase64Binary));
        Rfc3161.TokenCheck c = CertificateTimestamps.verify(g, DOC, Optional.of(tsa.anchors())).get(0).token();
        assertFalse(c.valid(), "tampered token");
    }

    @Test
    void tsaCertificateMustBeValidAtTheTokenTime() throws Exception {
        Instant now = Instant.now().truncatedTo(ChronoUnit.SECONDS);
        TestTsa expired = new TestTsa("CN=expired TSA", now.minus(Duration.ofDays(30)), now.minus(Duration.ofDays(1)));
        Graph g = signedDocument("certified");
        CertificateTimestamps.attach(g, DOC, expired.token(CertificateTimestamps.messageImprint(g, DOC)), null);
        Rfc3161.TokenCheck c = CertificateTimestamps.verify(g, DOC, Optional.of(expired.anchors())).get(0).token();
        assertFalse(c.signatureValid(), "issued after the TSA certificate expired");

        // Issued while the certificate was valid: still valid today.
        Graph old = signedDocument("certified");
        expired.at(now.minus(Duration.ofDays(10)));
        CertificateTimestamps.attach(old, DOC, expired.token(CertificateTimestamps.messageImprint(old, DOC)), null);
        Rfc3161.TokenCheck ok = CertificateTimestamps.verify(old, DOC, Optional.of(expired.anchors())).get(0).token();
        assertTrue(ok.valid(), () -> ok.problems().toString());
        assertEquals(Boolean.TRUE, ok.trusted(), "chain checked at the token's time");
    }

    @Test
    void replyMustMatchTheRequest() throws Exception {
        byte[] imprint = Rfc3161.sha256("x".getBytes());
        TimeStampRequest asked = Rfc3161.request(imprint, BigInteger.ONE);
        TimeStampRequest answered = Rfc3161.request(imprint, BigInteger.TWO);
        byte[] reply = tsa.reply(answered.getEncoded());
        assertThrows(TSPException.class, () -> Rfc3161.tokenFromReply(asked, reply), "nonce mismatch");
        assertNotNull(Rfc3161.tokenFromReply(answered, reply));
    }
}

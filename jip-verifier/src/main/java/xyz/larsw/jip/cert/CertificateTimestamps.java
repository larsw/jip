package xyz.larsw.jip.cert;

import java.io.IOException;
import java.security.cert.TrustAnchor;
import java.time.Instant;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;

import org.apache.jena.datatypes.xsd.XSDDatatype;
import org.apache.jena.graph.Graph;
import org.apache.jena.graph.GraphMemFactory;
import org.apache.jena.graph.Node;
import org.apache.jena.graph.NodeFactory;
import org.apache.jena.graph.Triple;
import org.apache.jena.vocabulary.RDF;
import org.bouncycastle.tsp.TSPException;

/**
 * RFC 3161 timestamps on a certificate: a time-stamping authority (TSA) co-signs the
 * certificate's Ed25519 signature, proving that the certificate existed at the TSA's time.
 * <p>
 * The message imprint is {@code SHA-256(signature)}, where {@code signature} is the raw
 * signature decoded from the proof's {@code sec:proofValue}. The signature covers the whole
 * certificate, so the timestamp does too (the same construction as a CAdES signature
 * time-stamp). A timestamp is attached after signing, as
 * <pre>
 * &lt;C&gt; jip:timestamp _:t .
 * _:t a jip:RFC3161Timestamp ;
 *     jip:timestampToken "...DER, base64..."^^xsd:base64Binary ;
 *     jip:timestampAuthority &lt;https://tsa.example/&gt; ;     # informational
 *     jip:timestampTime "..."^^xsd:dateTime .                # informational, copied from the token
 * </pre>
 * These triples are not part of the signed document: {@link #withoutTimestamps} removes them
 * before the Data Integrity proof is checked. Only the token is evidence; the other two values
 * are for convenience, and verification reports what the token says.
 */
public final class CertificateTimestamps {
    private CertificateTimestamps() {}

    /** A timestamp found on a certificate. */
    public record Attached(Node node, byte[] token, String authority) {}

    /** A checked timestamp: where it came from and what the check found. */
    public record Check(String authority, Rfc3161.TokenCheck token) {}

    /** The raw signature bytes from the certificate's single proof. */
    public static byte[] signature(Graph graph, Node certificate) {
        List<Node> proofs = graph.find(certificate, Vocab.secProof, Node.ANY).mapWith(Triple::getObject).toList();
        if ( proofs.size() != 1 )
            throw new IllegalArgumentException("Expected exactly one sec:proof, found " + proofs.size());
        List<Node> values = graph.find(proofs.get(0), Vocab.secProofValue, Node.ANY).mapWith(Triple::getObject).toList();
        if ( values.size() != 1 || !values.get(0).isLiteral() )
            throw new IllegalArgumentException("Proof has no single sec:proofValue");
        return Base58.decodeMultibase(values.get(0).getLiteralLexicalForm());
    }

    /** What a TSA is asked to sign: SHA-256 of the certificate's signature. */
    public static byte[] messageImprint(Graph graph, Node certificate) {
        return Rfc3161.sha256(signature(graph, certificate));
    }

    /**
     * Attach a token (from {@link Rfc3161#tokenFromReply}) to a signed certificate.
     *
     * @param authority  the TSA endpoint the token came from, or null
     * @return the timestamp node
     */
    public static Node attach(Graph graph, Node certificate, byte[] token, String authority) {
        Instant genTime;
        try {
            genTime = Rfc3161.genTime(token);
        } catch (TSPException | IOException ex) {
            throw new IllegalArgumentException(ex.getMessage(), ex);
        }
        Node t = NodeFactory.createBlankNode();
        graph.add(certificate, Vocab.timestamp, t);
        graph.add(t, RDF.type.asNode(), Vocab.RFC3161Timestamp);
        graph.add(t, Vocab.timestampToken,
                  NodeFactory.createLiteralDT(Base64.getEncoder().encodeToString(token), XSDDatatype.XSDbase64Binary));
        if ( authority != null )
            graph.add(t, Vocab.timestampAuthority, NodeFactory.createURI(authority));
        graph.add(t, Vocab.timestampTime,
                  NodeFactory.createLiteralDT(DateTimeFormatter.ISO_INSTANT.format(genTime), XSDDatatype.XSDdateTime));
        return t;
    }

    /** The timestamps attached to {@code certificate}. */
    public static List<Attached> find(Graph graph, Node certificate) {
        List<Attached> out = new ArrayList<>();
        for ( Node t : graph.find(certificate, Vocab.timestamp, Node.ANY).mapWith(Triple::getObject).toList() ) {
            byte[] token = graph.find(t, Vocab.timestampToken, Node.ANY).mapWith(Triple::getObject)
                    .filterKeep(Node::isLiteral).nextOptional()
                    .map(n -> decodeBase64(n.getLiteralLexicalForm())).orElse(null);
            String authority = graph.find(t, Vocab.timestampAuthority, Node.ANY).mapWith(Triple::getObject)
                    .filterKeep(Node::isURI).nextOptional().map(Node::getURI).orElse(null);
            out.add(new Attached(t, token, authority));
        }
        return out;
    }

    /**
     * A copy of the graph without the timestamps of {@code certificate}: without the
     * {@code jip:timestamp} links and without the triples of the timestamp nodes. This is what the
     * Data Integrity proof signed.
     */
    public static Graph withoutTimestamps(Graph graph, Node certificate) {
        List<Triple> links = graph.find(certificate, Vocab.timestamp, Node.ANY).toList();
        Set<Node> nodes = new HashSet<>();
        links.forEach(t -> nodes.add(t.getObject()));
        Graph out = GraphMemFactory.createDefaultGraph();
        graph.find().forEachRemaining(t -> {
            if ( nodes.contains(t.getSubject()) || links.contains(t) )
                return;
            out.add(t);
        });
        return out;
    }

    /**
     * Check every timestamp on {@code certificate} against its signature.
     *
     * @param trustAnchors  anchors for the TSA certificates; empty to skip the chain check
     */
    public static List<Check> verify(Graph graph, Node certificate, Optional<Set<TrustAnchor>> trustAnchors) {
        List<Attached> attached = find(graph, certificate);
        if ( attached.isEmpty() )
            return List.of();
        byte[] imprint;
        try {
            imprint = messageImprint(graph, certificate);
        } catch (IllegalArgumentException ex) {
            return attached.stream()
                    .map(a -> new Check(a.authority(), Rfc3161.TokenCheck.unreadable("No signature to check against: " + ex.getMessage())))
                    .toList();
        }
        List<Check> checks = new ArrayList<>();
        for ( Attached a : attached ) {
            Rfc3161.TokenCheck check = a.token() == null
                    ? Rfc3161.TokenCheck.unreadable("Timestamp has no readable jip:timestampToken")
                    : Rfc3161.verify(a.token(), imprint, trustAnchors);
            checks.add(new Check(a.authority(), check));
        }
        return List.copyOf(checks);
    }

    private static byte[] decodeBase64(String lex) {
        try {
            return Base64.getMimeDecoder().decode(lex);
        } catch (IllegalArgumentException ex) {
            return null;
        }
    }
}

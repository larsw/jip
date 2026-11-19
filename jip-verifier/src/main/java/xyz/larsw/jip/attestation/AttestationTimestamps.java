package xyz.larsw.jip.attestation;

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
 * RFC 3161 timestamps on an attestation: a time-stamping authority (TSA) co-signs the
 * attestation's Ed25519 signature, proving that the attestation existed at the TSA's time.
 * <p>
 * The message imprint is {@code SHA-256(signature)}, where {@code signature} is the raw
 * signature decoded from the proof's {@code sec:proofValue}. The signature covers the whole
 * attestation, so the timestamp does too (the same construction as a CAdES signature
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
public final class AttestationTimestamps {
    private AttestationTimestamps() {}

    /** A timestamp found on an attestation. */
    public record Attached(Node node, byte[] token, String authority) {}

    /** A checked timestamp: where it came from and what the check found. */
    public record Check(String authority, Rfc3161.TokenCheck token) {}

    /** The raw signature bytes from the attestation's single proof. */
    public static byte[] signature(Graph graph, Node attestation) {
        List<Node> proofs = graph.find(attestation, Vocab.secProof, Node.ANY).mapWith(Triple::getObject).toList();
        if ( proofs.size() != 1 )
            throw new IllegalArgumentException("Expected exactly one sec:proof, found " + proofs.size());
        List<Node> values = graph.find(proofs.get(0), Vocab.secProofValue, Node.ANY).mapWith(Triple::getObject).toList();
        if ( values.size() != 1 || !values.get(0).isLiteral() )
            throw new IllegalArgumentException("Proof has no single sec:proofValue");
        return Base58.decodeMultibase(values.get(0).getLiteralLexicalForm());
    }

    /** What a TSA is asked to sign: SHA-256 of the attestation's signature. */
    public static byte[] messageImprint(Graph graph, Node attestation) {
        return Rfc3161.sha256(signature(graph, attestation));
    }

    /**
     * Attach a token (from {@link Rfc3161#tokenFromReply}) to a signed attestation.
     *
     * @param authority  the TSA endpoint the token came from, or null
     * @return the timestamp node
     */
    public static Node attach(Graph graph, Node attestation, byte[] token, String authority) {
        Instant genTime;
        try {
            genTime = Rfc3161.genTime(token);
        } catch (TSPException | IOException ex) {
            throw new IllegalArgumentException(ex.getMessage(), ex);
        }
        Node t = NodeFactory.createBlankNode();
        graph.add(attestation, Vocab.timestamp, t);
        graph.add(t, RDF.type.asNode(), Vocab.RFC3161Timestamp);
        graph.add(t, Vocab.timestampToken,
                  NodeFactory.createLiteralDT(Base64.getEncoder().encodeToString(token), XSDDatatype.XSDbase64Binary));
        if ( authority != null )
            graph.add(t, Vocab.timestampAuthority, NodeFactory.createURI(authority));
        graph.add(t, Vocab.timestampTime,
                  NodeFactory.createLiteralDT(DateTimeFormatter.ISO_INSTANT.format(genTime), XSDDatatype.XSDdateTime));
        return t;
    }

    /** The timestamps attached to {@code attestation}. */
    public static List<Attached> find(Graph graph, Node attestation) {
        List<Attached> out = new ArrayList<>();
        for ( Node t : graph.find(attestation, Vocab.timestamp, Node.ANY).mapWith(Triple::getObject).toList() ) {
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
     * A copy of the graph without the timestamps of {@code attestation}: without the
     * {@code jip:timestamp} links and without the triples of the timestamp nodes. This is what the
     * Data Integrity proof signed.
     */
    public static Graph withoutTimestamps(Graph graph, Node attestation) {
        List<Triple> links = graph.find(attestation, Vocab.timestamp, Node.ANY).toList();
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
     * Check every timestamp on {@code attestation} against its signature.
     *
     * @param trustAnchors  anchors for the TSA certificates; empty to skip the chain check
     */
    public static List<Check> verify(Graph graph, Node attestation, Optional<Set<TrustAnchor>> trustAnchors) {
        List<Attached> attached = find(graph, attestation);
        if ( attached.isEmpty() )
            return List.of();
        byte[] imprint;
        try {
            imprint = messageImprint(graph, attestation);
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

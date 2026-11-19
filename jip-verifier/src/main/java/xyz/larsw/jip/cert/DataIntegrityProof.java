package xyz.larsw.jip.cert;

import java.time.Instant;
import java.time.format.DateTimeFormatter;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import org.apache.jena.datatypes.RDFDatatype;
import org.apache.jena.datatypes.TypeMapper;
import org.apache.jena.datatypes.xsd.XSDDatatype;
import org.apache.jena.graph.Graph;
import org.apache.jena.graph.Node;
import org.apache.jena.graph.NodeFactory;
import org.apache.jena.graph.Triple;
import org.apache.jena.graph.GraphMemFactory;
import org.apache.jena.vocabulary.RDF;
import xyz.larsw.jip.canon.RdfCanonicalizer;

/**
 * W3C Data Integrity proofs with the {@code eddsa-rdfc-2022} cryptosuite
 * (https://www.w3.org/TR/vc-di-eddsa/), applied at the RDF level.
 * <ul>
 * <li>Unsecured document: the graph without the proof node's triples and without
 * {@code <doc> sec:proof _:p}.</li>
 * <li>Proof configuration: the proof node's triples without {@code sec:proofValue}.</li>
 * <li>hashData = SHA-256(RDFC-1.0(proofConfig)) || SHA-256(RDFC-1.0(document)).</li>
 * <li>proofValue = multibase base58btc of the Ed25519 signature of hashData.</li>
 * </ul>
 * The proof is embedded as plain triples, not as the JSON-LD {@code @graph} container that the
 * VC serialization uses.
 */
public final class DataIntegrityProof {
    private DataIntegrityProof() {}

    public static final String CRYPTOSUITE = "eddsa-rdfc-2022";

    /** Outcome of a verification. */
    public record Verification(boolean valid, String verificationMethod, Instant created, List<String> problems) {
        static Verification fail(String problem) {
            return new Verification(false, null, null, List.of(problem));
        }
    }

    /**
     * Sign {@code graph} as a document about {@code subject}: adds the proof triples.
     *
     * @return the proof node
     */
    public static Node sign(Graph graph, Node subject, ProofSigner signer, Instant created) {
        Node proof = NodeFactory.createBlankNode();
        Graph proofConfig = proofConfig(proof, signer.verificationMethod(), created);
        byte[] hashData = hashData(proofConfig, graph);
        String proofValue = Base58.encodeMultibase(signer.sign(hashData));

        proofConfig.find().forEach(graph::add);
        graph.add(subject, Vocab.secProof, proof);
        graph.add(proof, Vocab.secProofValue, NodeFactory.createLiteralDT(proofValue, datatype(Vocab.secMultibase)));
        return proof;
    }

    /** The proof configuration triples (everything but {@code sec:proofValue}). */
    public static Graph proofConfig(Node proof, String verificationMethod, Instant created) {
        Graph g = GraphMemFactory.createDefaultGraph();
        String createdLex = DateTimeFormatter.ISO_INSTANT.format(created.truncatedTo(ChronoUnit.SECONDS));
        g.add(proof, RDF.type.asNode(), Vocab.secDataIntegrityProof);
        g.add(proof, Vocab.secCryptosuite, NodeFactory.createLiteralDT(CRYPTOSUITE, datatype(Vocab.secCryptosuiteString)));
        g.add(proof, Vocab.dctermsCreated, NodeFactory.createLiteralDT(createdLex, XSDDatatype.XSDdateTime));
        g.add(proof, Vocab.secVerificationMethod, NodeFactory.createURI(verificationMethod));
        g.add(proof, Vocab.secProofPurpose, Vocab.secAssertionMethod);
        return g;
    }

    /** SHA-256(canon(proofConfig)) || SHA-256(canon(document)). */
    public static byte[] hashData(Graph proofConfig, Graph unsecuredDocument) {
        RdfCanonicalizer canon = RdfCanonicalizer.standard();
        byte[] proofHash = RdfCanonicalizer.sha256(canon.canonicalize(proofConfig));
        byte[] docHash = RdfCanonicalizer.sha256(canon.canonicalize(unsecuredDocument));
        byte[] combined = new byte[proofHash.length + docHash.length];
        System.arraycopy(proofHash, 0, combined, 0, proofHash.length);
        System.arraycopy(docHash, 0, combined, proofHash.length, docHash.length);
        return combined;
    }

    /**
     * Verify the single proof attached to {@code subject} in {@code graph}. The public key is
     * taken from the {@code did:key} verification method.
     */
    public static Verification verify(Graph graph, Node subject) {
        List<Triple> links = graph.find(subject, Vocab.secProof, Node.ANY).toList();
        if ( links.size() != 1 )
            return Verification.fail("Expected exactly one sec:proof, found " + links.size());
        Node proof = links.get(0).getObject();

        List<Triple> proofTriples = graph.find(proof, Node.ANY, Node.ANY).toList();
        Graph document = GraphMemFactory.createDefaultGraph();
        graph.find().forEach(t -> {
            if ( t.getSubject().equals(proof) || t.equals(links.get(0)) )
                return;
            document.add(t);
        });
        Graph proofConfig = GraphMemFactory.createDefaultGraph();
        proofTriples.stream().filter(t -> !t.getPredicate().equals(Vocab.secProofValue)).forEach(proofConfig::add);

        List<String> problems = new ArrayList<>();
        Optional<String> cryptosuite = single(proofTriples, Vocab.secCryptosuite).filter(Node::isLiteral)
                .map(Node::getLiteralLexicalForm);
        if ( !cryptosuite.map(CRYPTOSUITE::equals).orElse(false) )
            problems.add("Unsupported or missing cryptosuite: " + cryptosuite.orElse("(none)"));
        if ( !graph.contains(proof, RDF.type.asNode(), Vocab.secDataIntegrityProof) )
            problems.add("Proof is not a sec:DataIntegrityProof");
        if ( !graph.contains(proof, Vocab.secProofPurpose, Vocab.secAssertionMethod) )
            problems.add("Proof purpose is not sec:assertionMethod");
        Optional<Node> vm = single(proofTriples, Vocab.secVerificationMethod).filter(Node::isURI);
        Optional<String> proofValue = single(proofTriples, Vocab.secProofValue).filter(Node::isLiteral)
                .map(Node::getLiteralLexicalForm);
        Instant created = single(proofTriples, Vocab.dctermsCreated).filter(Node::isLiteral)
                .map(n -> parseInstant(n.getLiteralLexicalForm())).orElse(null);
        if ( vm.isEmpty() )
            problems.add("Missing verification method");
        if ( proofValue.isEmpty() )
            problems.add("Missing proof value");
        if ( !problems.isEmpty() )
            return new Verification(false, vm.map(Node::getURI).orElse(null), created, problems);

        String verificationMethod = vm.get().getURI();
        byte[] publicKey;
        byte[] signature;
        try {
            publicKey = DidKey.publicKey(verificationMethod);
            signature = Base58.decodeMultibase(proofValue.get());
        } catch (IllegalArgumentException ex) {
            return new Verification(false, verificationMethod, created, List.of(ex.getMessage()));
        }
        boolean ok = DidKey.verify(publicKey, hashData(proofConfig, document), signature);
        return new Verification(ok, verificationMethod, created, ok ? List.of() : List.of("Signature does not verify"));
    }

    private static Optional<Node> single(List<Triple> triples, Node predicate) {
        List<Node> objs = triples.stream().filter(t -> t.getPredicate().equals(predicate)).map(Triple::getObject).toList();
        return objs.size() == 1 ? Optional.of(objs.get(0)) : Optional.empty();
    }

    private static Instant parseInstant(String lex) {
        try {
            return Instant.parse(lex);
        } catch (RuntimeException ex) {
            return null;
        }
    }

    /** A datatype known only by its IRI (sec:cryptosuiteString, sec:multibase). */
    private static RDFDatatype datatype(Node iri) {
        return TypeMapper.getInstance().getSafeTypeByName(iri.getURI());
    }
}

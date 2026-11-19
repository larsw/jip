package xyz.larsw.jip.attestation;

import java.time.Instant;
import java.time.format.DateTimeFormatter;
import java.util.List;
import java.util.UUID;

import org.apache.jena.datatypes.xsd.XSDDatatype;
import org.apache.jena.graph.Graph;
import org.apache.jena.graph.GraphMemFactory;
import org.apache.jena.graph.Node;
import org.apache.jena.graph.NodeFactory;
import org.apache.jena.vocabulary.RDF;

/**
 * Builds and signs the PROV-O result attestation (see docs/DESIGN.md §3).
 */
public final class AttestationBuilder {
    private AttestationBuilder() {}

    /** Everything an attestation states. */
    public record Input(UUID attestationId,
                        UUID databaseId,
                        String datasetIRI,          // nullable
                        long dataVersion,
                        List<String> variables,     // attested variables, sorted
                        boolean ordered,
                        int solutionCount,
                        String digest,              // hex SHA-256 of the RDFC-1.0 canonical rs: encoding
                        String servicePattern,
                        String queryText,           // nullable
                        Instant started,
                        Instant ended) {}

    public static Node attestationNode(UUID attestationId) {
        return NodeFactory.createURI("urn:uuid:" + attestationId);
    }

    public static Node databaseNode(UUID databaseId) {
        return NodeFactory.createURI("urn:uuid:" + databaseId);
    }

    public static Node datasetStateNode(UUID databaseId, long version) {
        return NodeFactory.createURI("urn:uuid:" + databaseId + "#v" + version);
    }

    /** Build the attestation graph and sign it with {@code key}. */
    public static Graph buildSigned(Input in, ProvenanceSigner key, String agentLabel) {
        Graph g = build(in, key, agentLabel);
        DataIntegrityProof.sign(g, attestationNode(in.attestationId()), key, in.ended());
        return g;
    }

    /** Build the (unsigned) attestation graph. */
    public static Graph build(Input in, ProvenanceSigner key, String agentLabel) {
        Graph g = GraphMemFactory.createDefaultGraph();
        Node attestationIri = attestationNode(in.attestationId());
        Node result = NodeFactory.createURI(attestationIri.getURI() + "#result");
        Node exec = NodeFactory.createURI(attestationIri.getURI() + "#exec");
        Node state = datasetStateNode(in.databaseId(), in.dataVersion());
        Node dataset = in.datasetIRI() != null ? NodeFactory.createURI(in.datasetIRI()) : databaseNode(in.databaseId());
        Node agent = NodeFactory.createURI(key.didKey());
        Node type = RDF.type.asNode();

        g.add(attestationIri, type, Vocab.ResultAttestation);
        g.add(attestationIri, type, Vocab.provEntity);
        g.add(attestationIri, Vocab.attests, result);

        g.add(result, type, Vocab.provEntity);
        g.add(result, type, Vocab.SolutionSequence);
        g.add(result, Vocab.provWasGeneratedBy, exec);
        g.add(result, Vocab.provWasDerivedFrom, state);
        for ( String v : in.variables() )
            g.add(result, Vocab.variable, NodeFactory.createLiteralString(v));
        g.add(result, Vocab.ordered, NodeFactory.createLiteralDT(Boolean.toString(in.ordered()), XSDDatatype.XSDboolean));
        g.add(result, Vocab.solutionCount, integer(in.solutionCount()));
        g.add(result, Vocab.canonicalization, Vocab.RDFC_1_0);
        g.add(result, Vocab.digestAlgorithm, NodeFactory.createLiteralString("SHA-256"));
        g.add(result, Vocab.digest, NodeFactory.createLiteralString(in.digest()));

        g.add(exec, type, Vocab.provActivity);
        g.add(exec, type, Vocab.QueryExecution);
        g.add(exec, Vocab.provUsed, state);
        g.add(exec, Vocab.provWasAssociatedWith, agent);
        g.add(exec, Vocab.provStartedAtTime, dateTime(in.started()));
        g.add(exec, Vocab.provEndedAtTime, dateTime(in.ended()));
        g.add(exec, Vocab.servicePattern, NodeFactory.createLiteralString(in.servicePattern()));
        if ( in.queryText() != null )
            g.add(exec, Vocab.queryText, NodeFactory.createLiteralString(in.queryText()));

        g.add(state, type, Vocab.provEntity);
        g.add(state, type, Vocab.DatasetState);
        g.add(state, Vocab.provSpecializationOf, dataset);
        g.add(state, Vocab.dataVersion, integer(in.dataVersion()));

        g.add(agent, type, Vocab.provSoftwareAgent);
        g.add(agent, Vocab.rdfsLabel, NodeFactory.createLiteralString(agentLabel));
        return g;
    }

    private static Node integer(long n) {
        return NodeFactory.createLiteralDT(Long.toString(n), XSDDatatype.XSDinteger);
    }

    private static Node dateTime(Instant t) {
        return NodeFactory.createLiteralDT(DateTimeFormatter.ISO_INSTANT.format(t), XSDDatatype.XSDdateTime);
    }
}

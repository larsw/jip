package xyz.larsw.jip.attestation;

import org.apache.jena.graph.Node;
import org.apache.jena.graph.NodeFactory;

/** RDF terms used in attestations and proofs. */
public final class Vocab {
    private Vocab() {}

    /**
     * Namespace of the jip: vocabulary. This is the only definition; {@code JIP.NS} in the
     * Fuseki module refers to it.
     */
    public static final String NS = "https://larsw.xyz/jip/";

    public static final String PROV = "http://www.w3.org/ns/prov#";
    public static final String SEC = "https://w3id.org/security#";
    public static final String DCTERMS = "http://purl.org/dc/terms/";
    public static final String RDFS = "http://www.w3.org/2000/01/rdf-schema#";
    public static final String XSD = "http://www.w3.org/2001/XMLSchema#";

    // PROV-O
    public static final Node provEntity = uri(PROV, "Entity");
    public static final Node provActivity = uri(PROV, "Activity");
    public static final Node provSoftwareAgent = uri(PROV, "SoftwareAgent");
    public static final Node provWasGeneratedBy = uri(PROV, "wasGeneratedBy");
    public static final Node provWasDerivedFrom = uri(PROV, "wasDerivedFrom");
    public static final Node provUsed = uri(PROV, "used");
    public static final Node provWasAssociatedWith = uri(PROV, "wasAssociatedWith");
    public static final Node provStartedAtTime = uri(PROV, "startedAtTime");
    public static final Node provEndedAtTime = uri(PROV, "endedAtTime");
    public static final Node provSpecializationOf = uri(PROV, "specializationOf");

    // Data Integrity (https://w3id.org/security#)
    public static final Node secProof = uri(SEC, "proof");
    public static final Node secDataIntegrityProof = uri(SEC, "DataIntegrityProof");
    public static final Node secCryptosuite = uri(SEC, "cryptosuite");
    public static final Node secCryptosuiteString = uri(SEC, "cryptosuiteString");
    public static final Node secVerificationMethod = uri(SEC, "verificationMethod");
    public static final Node secProofPurpose = uri(SEC, "proofPurpose");
    public static final Node secAssertionMethod = uri(SEC, "assertionMethod");
    public static final Node secProofValue = uri(SEC, "proofValue");
    public static final Node secMultibase = uri(SEC, "multibase");
    public static final Node dctermsCreated = uri(DCTERMS, "created");

    public static final Node rdfsLabel = uri(RDFS, "label");

    // jip: attestation vocabulary
    public static final Node ResultAttestation = uri(NS, "ResultAttestation");
    public static final Node SolutionSequence = uri(NS, "SolutionSequence");
    public static final Node QueryExecution = uri(NS, "QueryExecution");
    public static final Node DatasetState = uri(NS, "DatasetState");
    public static final Node attests = uri(NS, "attests");
    public static final Node variable = uri(NS, "variable");
    public static final Node ordered = uri(NS, "ordered");
    public static final Node solutionCount = uri(NS, "solutionCount");
    public static final Node canonicalization = uri(NS, "canonicalization");
    public static final Node digestAlgorithm = uri(NS, "digestAlgorithm");
    public static final Node digest = uri(NS, "digest");
    public static final Node servicePattern = uri(NS, "servicePattern");
    public static final Node queryText = uri(NS, "queryText");
    public static final Node dataVersion = uri(NS, "dataVersion");

    // jip: RFC 3161 timestamps (outside the signed document; see AttestationTimestamps)
    public static final Node RFC3161Timestamp = uri(NS, "RFC3161Timestamp");
    public static final Node timestamp = uri(NS, "timestamp");
    public static final Node timestampToken = uri(NS, "timestampToken");
    public static final Node timestampAuthority = uri(NS, "timestampAuthority");
    public static final Node timestampTime = uri(NS, "timestampTime");

    /** The RDFC-1.0 specification, identifying the canonicalization algorithm. */
    public static final Node RDFC_1_0 = NodeFactory.createURI("https://www.w3.org/TR/rdf-canon/");

    private static Node uri(String ns, String local) {
        return NodeFactory.createURI(ns + local);
    }
}

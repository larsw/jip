package xyz.larsw.jip;

import org.apache.jena.rdf.model.Property;
import org.apache.jena.rdf.model.Resource;
import org.apache.jena.rdf.model.ResourceFactory;
import org.apache.jena.sparql.util.Symbol;
import xyz.larsw.jip.attestation.Vocab;

/**
 * Names shared across the module: the vocabulary namespace, the
 * attest SERVICE IRI, assembler terms, context symbols and function IRIs.
 * <p>
 * The namespace is defined in the verifier library as {@link Vocab#NS}; change it there to
 * rename.
 */
public final class JIP {
    private JIP() {}

    /** Namespace for the custom vocabulary. */
    public static final String NS = Vocab.NS;

    /** The specially named SERVICE that attests its inner solution sequence. */
    public static final String SERVICE_ATTEST = "urn:x-provenance:attest";

    // ---- Assembler

    /** Dataset type: a TDB2 dataset with the persistent data version component attached. */
    public static final Resource VersionedDatasetTDB2 = resource("VersionedDatasetTDB2");
    /** Optional: IRI naming the logical dataset (used with prov:specializationOf). */
    public static final Property datasetIRI = property("datasetIRI");

    // ---- Context symbols

    /** Dataset context: the attached {@code DataVersionComponent}. */
    public static final Symbol symDataVersion = Symbol.create(NS + "dataVersionComponent");
    /** Server/dataset context: TDB2 location of the attestation store. */
    public static final Symbol symAttestationStore = Symbol.create(NS + "attestationStore");
    /** Server context: maximum number of solutions an attested SERVICE may return. */
    public static final Symbol symMaxSolutions = Symbol.create(NS + "maxSolutions");
    /** Server context: RFC 3161 TSA URLs in priority order (whitespace or comma separated). */
    public static final Symbol symTimestampAuthorities = Symbol.create(NS + "timestampAuthorities");
    /** Server context: {@code optional} (default) or {@code required}. */
    public static final Symbol symTimestampPolicy = Symbol.create(NS + "timestampPolicy");
    /** Server context: per-TSA request timeout in milliseconds (default 5000). */
    public static final Symbol symTimestampTimeout = Symbol.create(NS + "timestampTimeout");
    /** Server context: {@code async} (default) or {@code sync}. */
    public static final Symbol symTimestampMode = Symbol.create(NS + "timestampMode");
    /** Server context: async + optional policy: how long to retry, in milliseconds (default 600000). */
    public static final Symbol symTimestampMaxWait = Symbol.create(NS + "timestampMaxWait");

    /** Server context: record the authenticated user in attestations ({@code true}, the default, or {@code false}). */
    public static final Symbol symRecordRequester = Symbol.create(NS + "recordRequester");
    /** Query context: the requester ({@code Requester}) for embedded use, instead of the HTTP request's user. */
    public static final Symbol symRequestUser = Symbol.create(NS + "requestUser");

    // ---- Attestation store

    /** Named graph in the attestation store listing the attestations waiting for a timestamp. */
    public static final Resource PENDING_TIMESTAMPS = resource("pendingTimestamps");
    /** Named graph in the attestation store recording every signing key the server has used. */
    public static final Resource SIGNING_KEYS = resource("signingKeys");
    /** In {@link #SIGNING_KEYS}: when a key (its did:key) became the signing key. */
    public static final Property activatedAt = property("activatedAt");
    /** In {@link #PENDING_TIMESTAMPS}: when an attestation started waiting for its timestamp. */
    public static final Property timestampPendingSince = property("timestampPendingSince");

    // ---- SPARQL functions

    /** {@code jip:dataVersion()} : persistent version of the snapshot being read. */
    public static final String FN_DATA_VERSION = NS + "dataVersion";
    /** {@code jip:tdbDataVersion()} : TDB2's internal, volatile data version. */
    public static final String FN_TDB_DATA_VERSION = NS + "tdbDataVersion";

    // ---- HTTP

    public static final String HEADER_DATASET_VERSION = "X-Dataset-Version";
    public static final String HEADER_DATASET_ID = "X-Dataset-Id";

    static Resource resource(String localName) {
        return ResourceFactory.createResource(NS + localName);
    }

    static Property property(String localName) {
        return ResourceFactory.createProperty(NS + localName);
    }
}

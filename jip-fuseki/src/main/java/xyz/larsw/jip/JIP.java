package xyz.larsw.jip;

import org.apache.jena.rdf.model.Property;
import org.apache.jena.rdf.model.Resource;
import org.apache.jena.rdf.model.ResourceFactory;
import org.apache.jena.sparql.util.Symbol;
import xyz.larsw.jip.cert.Vocab;

/**
 * Names shared across the module: the vocabulary namespace, the
 * certify SERVICE IRI, assembler terms, context symbols and function IRIs.
 * <p>
 * The namespace is defined in the verifier library as {@link Vocab#NS}; change it there to
 * rename.
 */
public final class JIP {
    private JIP() {}

    /** Namespace for the custom vocabulary. */
    public static final String NS = Vocab.NS;

    /** The specially named SERVICE that certifies its inner solution sequence. */
    public static final String SERVICE_CERTIFY = "urn:x-provenance:certify";

    // ---- Assembler

    /** Dataset type: a TDB2 dataset with the persistent data version component attached. */
    public static final Resource VersionedDatasetTDB2 = resource("VersionedDatasetTDB2");
    /** Optional: IRI naming the logical dataset (used with prov:specializationOf). */
    public static final Property datasetIRI = property("datasetIRI");

    // ---- Context symbols

    /** Dataset context: the attached {@code DataVersionComponent}. */
    public static final Symbol symDataVersion = Symbol.create(NS + "dataVersionComponent");
    /** Server/dataset context: TDB2 location of the certificate store. */
    public static final Symbol symCertificateStore = Symbol.create(NS + "certificateStore");
    /** Server context: maximum number of solutions a certified SERVICE may return. */
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

    // ---- Certificate store

    /** Named graph in the certificate store listing the certificates waiting for a timestamp. */
    public static final Resource PENDING_TIMESTAMPS = resource("pendingTimestamps");
    /** In {@link #PENDING_TIMESTAMPS}: when a certificate started waiting for its timestamp. */
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

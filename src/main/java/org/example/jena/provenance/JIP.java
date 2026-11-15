package org.example.jena.provenance;

import org.apache.jena.rdf.model.Property;
import org.apache.jena.rdf.model.Resource;
import org.apache.jena.rdf.model.ResourceFactory;
import org.apache.jena.sparql.util.Symbol;

/**
 * Names shared across the module: the placeholder vocabulary namespace, the
 * certify SERVICE IRI, assembler terms, context symbols and function IRIs.
 * <p>
 * The namespace is a placeholder ({@code example.org}); change {@link #NS} to rename.
 */
public final class JIP {
    private JIP() {}

    /** Placeholder namespace for the custom vocabulary. */
    public static final String NS = "http://example.org/jip#";

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

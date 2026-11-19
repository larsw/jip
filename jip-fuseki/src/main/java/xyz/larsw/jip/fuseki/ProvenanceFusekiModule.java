package xyz.larsw.jip.fuseki;

import java.util.Set;

import org.apache.jena.fuseki.main.FusekiServer;
import org.apache.jena.fuseki.main.sys.FusekiAutoModule;
import org.apache.jena.query.ARQ;
import org.apache.jena.rdf.model.Model;
import xyz.larsw.jip.cert.ProvenanceKeys;
import xyz.larsw.jip.cert.ProvenanceSigner;
import xyz.larsw.jip.cert.TimestampAuthorities;
import xyz.larsw.jip.sys.InitJIP;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Fuseki integration, loaded automatically from the classpath (ServiceLoader):
 * the {@code /$/provenance/*} endpoints and the data version response header filter.
 * <p>
 * The assembler, functions and certify SERVICE are registered by {@link InitJIP} (Jena system
 * initialization) and do not depend on Fuseki.
 */
public class ProvenanceFusekiModule implements FusekiAutoModule {
    private static final Logger LOG = LoggerFactory.getLogger(ProvenanceFusekiModule.class);

    @Override
    public String name() {
        return "jena-intrinsic-provenance";
    }

    @Override
    public void start() {
        InitJIP.init();
    }

    @Override
    public void prepare(FusekiServer.Builder builder, Set<String> datasetNames, Model configModel) {
        builder.addServlet("/$/provenance/*", new ProvenanceServlet());
        builder.addFilter("/*", new DataVersionHeaderFilter());
    }

    @Override
    public void serverBeforeStarting(FusekiServer server) {
        // Load (or generate) the key at startup so problems show early and the did:key is logged.
        ProvenanceSigner signer = ProvenanceKeys.get();
        LOG.info("Provenance signer: {} {}, {}", signer.kind(), signer.didKey(), signer.description());
    }

    @Override
    public void serverAfterStarting(FusekiServer server) {
        // Certificates whose timestamp was still being fetched when the server stopped.
        try {
            TimestampAuthorities.resumePending(ARQ.getContext());
        } catch (RuntimeException ex) {
            LOG.warn("Could not resume pending RFC 3161 timestamps: {}", ex.getMessage());
        }
    }
}

package org.example.jena.provenance.fuseki;

import java.util.Set;

import org.apache.jena.fuseki.main.FusekiServer;
import org.apache.jena.fuseki.main.sys.FusekiAutoModule;
import org.apache.jena.rdf.model.Model;
import org.example.jena.provenance.cert.ProvenanceKeys;
import org.example.jena.provenance.cert.SigningKey;
import org.example.jena.provenance.sys.InitJIP;
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
        SigningKey key = ProvenanceKeys.get();
        LOG.info("Provenance signing key: {} ({})", key.didKey(), ProvenanceKeys.keyFile());
    }
}

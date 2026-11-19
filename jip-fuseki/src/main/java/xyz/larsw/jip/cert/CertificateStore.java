package xyz.larsw.jip.cert;

import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

import org.apache.jena.graph.Graph;
import org.apache.jena.graph.GraphMemFactory;
import org.apache.jena.graph.Node;
import org.apache.jena.query.QueryExecException;
import org.apache.jena.sparql.core.DatasetGraph;
import org.apache.jena.sparql.util.Context;
import org.apache.jena.system.Txn;
import org.apache.jena.tdb2.DatabaseMgr;
import xyz.larsw.jip.JIP;
import xyz.larsw.jip.version.DataVersion;

/**
 * Where signed certificates are kept: one named graph per certificate, named by the
 * certificate IRI, in a dataset separate from the certified data.
 */
public interface CertificateStore {

    void store(Node certificate, Graph graph);

    Optional<Graph> get(Node certificate);

    /** A store over a transactional dataset (normally TDB2). */
    static CertificateStore over(DatasetGraph dsg) {
        if ( DataVersion.find(dsg).isPresent() )
            throw new IllegalArgumentException("The certificate store must not be a versioned dataset "
                                               + "(certificate writes would bump its data version)");
        return new DatasetCertificateStore(dsg);
    }

    /**
     * The store configured in the context ({@code jip:certificateStore}): a TDB2 location string,
     * a {@link DatasetGraph} or a {@link CertificateStore}.
     *
     * @throws QueryExecException if none is configured
     */
    static CertificateStore fromContext(Context context) {
        Object v = context == null ? null : context.get(JIP.symCertificateStore);
        if ( v instanceof CertificateStore s )
            return s;
        if ( v instanceof DatasetGraph dsg )
            return over(dsg);
        if ( v instanceof String location && !location.isBlank() )
            return DatasetCertificateStore.forLocation(location.strip());
        if ( v instanceof Node n && n.isLiteral() )
            return DatasetCertificateStore.forLocation(n.getLiteralLexicalForm().strip());
        throw new QueryExecException("No certificate store configured: set " + JIP.symCertificateStore.getSymbol()
                                     + " (ja:context) to a TDB2 location");
    }

    /** Implementation over a {@link DatasetGraph}. */
    final class DatasetCertificateStore implements CertificateStore {
        private static final Map<String, CertificateStore> byLocation = new ConcurrentHashMap<>();
        private final DatasetGraph dsg;

        private DatasetCertificateStore(DatasetGraph dsg) {
            this.dsg = dsg;
        }

        static CertificateStore forLocation(String location) {
            // TDB2 shares one connection per location, so this is the same database a
            // Fuseki service on that location uses.
            return byLocation.computeIfAbsent(location, loc -> over(DatabaseMgr.connectDatasetGraph(loc)));
        }

        @Override
        public void store(Node certificate, Graph graph) {
            Txn.executeWrite(dsg, () -> {
                dsg.removeGraph(certificate);
                dsg.addGraph(certificate, graph);
            });
        }

        @Override
        public Optional<Graph> get(Node certificate) {
            return Txn.calculateRead(dsg, () -> {
                if ( !dsg.containsGraph(certificate) )
                    return Optional.empty();
                Graph copy = GraphMemFactory.createDefaultGraph();
                dsg.getGraph(certificate).find().forEach(copy::add);
                return copy.isEmpty() ? Optional.empty() : Optional.of(copy);
            });
        }
    }
}

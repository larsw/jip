package xyz.larsw.jip.cert;

import java.time.Instant;
import java.time.format.DateTimeFormatter;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

import org.apache.jena.datatypes.xsd.XSDDatatype;
import org.apache.jena.graph.Graph;
import org.apache.jena.graph.GraphMemFactory;
import org.apache.jena.graph.Node;
import org.apache.jena.graph.NodeFactory;
import org.apache.jena.query.QueryExecException;
import org.apache.jena.sparql.core.DatasetGraph;
import org.apache.jena.sparql.core.Quad;
import org.apache.jena.sparql.util.Context;
import org.apache.jena.system.Txn;
import org.apache.jena.tdb2.DatabaseMgr;
import xyz.larsw.jip.JIP;
import xyz.larsw.jip.version.DataVersion;

/**
 * Where signed certificates are kept: one named graph per certificate, named by the
 * certificate IRI, in a dataset separate from the certified data.
 * <p>
 * A certificate whose RFC 3161 timestamp is still being fetched is <em>pending</em>: it is
 * stored, signed, and recorded in the graph {@link JIP#PENDING_TIMESTAMPS} as
 * {@code <C> jip:timestampPendingSince "..."^^xsd:dateTime}. Storing it and marking it pending
 * happen in one transaction, and so do adding the timestamp and clearing the mark, so a crash
 * leaves either a pending certificate (resumed on restart) or a finished one.
 */
public interface CertificateStore {

    void store(Node certificate, Graph graph);

    Optional<Graph> get(Node certificate);

    /** Store a signed certificate and mark it as waiting for its timestamp. */
    void storePending(Node certificate, Graph graph, Instant since);

    /**
     * Add {@code additions} (the timestamp triples; may be empty) to a pending certificate and
     * clear its pending mark, in one transaction. Does nothing if the certificate is no longer
     * pending, so a certificate can't get a second timestamp from a competing worker.
     *
     * @return whether the certificate was pending
     */
    boolean completePending(Node certificate, Graph additions);

    /** When the certificate started waiting for its timestamp; empty if it isn't waiting. */
    Optional<Instant> pendingSince(Node certificate);

    /** All certificates waiting for a timestamp. */
    List<Node> pending();

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

    /** Whether a certificate store is configured in the context. */
    static boolean isConfigured(Context context) {
        return context != null && context.get(JIP.symCertificateStore) != null;
    }

    /** Implementation over a {@link DatasetGraph}. */
    final class DatasetCertificateStore implements CertificateStore {
        private static final Map<String, CertificateStore> byLocation = new ConcurrentHashMap<>();
        private static final Node PENDING = JIP.PENDING_TIMESTAMPS.asNode();
        private static final Node SINCE = JIP.timestampPendingSince.asNode();
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

        @Override
        public void storePending(Node certificate, Graph graph, Instant since) {
            Node time = NodeFactory.createLiteralDT(DateTimeFormatter.ISO_INSTANT.format(since), XSDDatatype.XSDdateTime);
            Txn.executeWrite(dsg, () -> {
                dsg.removeGraph(certificate);
                dsg.addGraph(certificate, graph);
                dsg.deleteAny(PENDING, certificate, SINCE, Node.ANY);
                dsg.add(PENDING, certificate, SINCE, time);
            });
        }

        @Override
        public boolean completePending(Node certificate, Graph additions) {
            return Txn.calculateWrite(dsg, () -> {
                if ( !dsg.contains(PENDING, certificate, SINCE, Node.ANY) )
                    return false;
                additions.find().forEach(t -> dsg.add(new Quad(certificate, t)));
                dsg.deleteAny(PENDING, certificate, SINCE, Node.ANY);
                return true;
            });
        }

        @Override
        public Optional<Instant> pendingSince(Node certificate) {
            return Txn.calculateRead(dsg, () -> {
                var it = dsg.find(PENDING, certificate, SINCE, Node.ANY);
                if ( !it.hasNext() )
                    return Optional.empty();
                Node o = it.next().getObject();
                try {
                    return Optional.of(Instant.parse(o.getLiteralLexicalForm()));
                } catch (RuntimeException ex) {
                    return Optional.of(Instant.EPOCH);
                }
            });
        }

        @Override
        public List<Node> pending() {
            return Txn.calculateRead(dsg, () -> dsg.stream(PENDING, Node.ANY, SINCE, Node.ANY).map(Quad::getSubject).distinct().toList());
        }
    }
}

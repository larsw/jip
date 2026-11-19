package xyz.larsw.jip.attestation;

import java.time.Instant;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
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
 * Where signed attestations are kept: one named graph per attestation, named by the
 * attestation IRI, in a dataset separate from the attested data.
 * <p>
 * An attestation whose RFC 3161 timestamp is still being fetched is <em>pending</em>: it is
 * stored, signed, and recorded in the graph {@link JIP#PENDING_TIMESTAMPS} as
 * {@code <C> jip:timestampPendingSince "..."^^xsd:dateTime}. Storing it and marking it pending
 * happen in one transaction, and so do adding the timestamp and clearing the mark, so a crash
 * leaves either a pending attestation (resumed on restart) or a finished one.
 */
public interface AttestationStore {

    void store(Node attestation, Graph graph);

    Optional<Graph> get(Node attestation);

    /** Store a signed attestation and mark it as waiting for its timestamp. */
    void storePending(Node attestation, Graph graph, Instant since);

    /**
     * Add {@code additions} (the timestamp triples; may be empty) to a pending attestation and
     * clear its pending mark, in one transaction. Does nothing if the attestation is no longer
     * pending, so an attestation can't get a second timestamp from a competing worker.
     *
     * @return whether the attestation was pending
     */
    boolean completePending(Node attestation, Graph additions);

    /** When the attestation started waiting for its timestamp; empty if it isn't waiting. */
    Optional<Instant> pendingSince(Node attestation);

    /** All attestations waiting for a timestamp. */
    List<Node> pending();

    /**
     * Record that the key {@code didKey} became the signing key at {@code at}, unless it already
     * is the most recently activated key. The history lives in the graph
     * {@link JIP#SIGNING_KEYS} as {@code <did:key:...> jip:activatedAt "..."^^xsd:dateTime}, one
     * value per activation.
     *
     * @return whether an activation was recorded
     */
    boolean recordKeyActivation(String didKey, Instant at);

    /** Every key ever activated, with its activation times in ascending order. */
    Map<String, List<Instant>> keyActivations();

    /** A store over a transactional dataset (normally TDB2). */
    static AttestationStore over(DatasetGraph dsg) {
        if ( DataVersion.find(dsg).isPresent() )
            throw new IllegalArgumentException("The attestation store must not be a versioned dataset "
                                               + "(attestation writes would bump its data version)");
        return new DatasetAttestationStore(dsg);
    }

    /**
     * The store configured in the context ({@code jip:attestationStore}): a TDB2 location string,
     * a {@link DatasetGraph} or a {@link AttestationStore}.
     *
     * @throws QueryExecException if none is configured
     */
    static AttestationStore fromContext(Context context) {
        Object v = context == null ? null : context.get(JIP.symAttestationStore);
        if ( v instanceof AttestationStore s )
            return s;
        if ( v instanceof DatasetGraph dsg )
            return over(dsg);
        if ( v instanceof String location && !location.isBlank() )
            return DatasetAttestationStore.forLocation(location.strip());
        if ( v instanceof Node n && n.isLiteral() )
            return DatasetAttestationStore.forLocation(n.getLiteralLexicalForm().strip());
        throw new QueryExecException("No attestation store configured: set " + JIP.symAttestationStore.getSymbol()
                                     + " (ja:context) to a TDB2 location");
    }

    /** Whether an attestation store is configured in the context. */
    static boolean isConfigured(Context context) {
        return context != null && context.get(JIP.symAttestationStore) != null;
    }

    /** Implementation over a {@link DatasetGraph}. */
    final class DatasetAttestationStore implements AttestationStore {
        private static final Map<String, AttestationStore> byLocation = new ConcurrentHashMap<>();
        private static final Node PENDING = JIP.PENDING_TIMESTAMPS.asNode();
        private static final Node SINCE = JIP.timestampPendingSince.asNode();
        private static final Node KEYS = JIP.SIGNING_KEYS.asNode();
        private static final Node ACTIVATED = JIP.activatedAt.asNode();
        private final DatasetGraph dsg;

        private DatasetAttestationStore(DatasetGraph dsg) {
            this.dsg = dsg;
        }

        static AttestationStore forLocation(String location) {
            // TDB2 shares one connection per location, so this is the same database a
            // Fuseki service on that location uses.
            return byLocation.computeIfAbsent(location, loc -> over(DatabaseMgr.connectDatasetGraph(loc)));
        }

        @Override
        public void store(Node attestation, Graph graph) {
            Txn.executeWrite(dsg, () -> {
                dsg.removeGraph(attestation);
                dsg.addGraph(attestation, graph);
            });
        }

        @Override
        public Optional<Graph> get(Node attestation) {
            return Txn.calculateRead(dsg, () -> {
                if ( !dsg.containsGraph(attestation) )
                    return Optional.empty();
                Graph copy = GraphMemFactory.createDefaultGraph();
                dsg.getGraph(attestation).find().forEach(copy::add);
                return copy.isEmpty() ? Optional.empty() : Optional.of(copy);
            });
        }

        @Override
        public void storePending(Node attestation, Graph graph, Instant since) {
            Node time = NodeFactory.createLiteralDT(DateTimeFormatter.ISO_INSTANT.format(since), XSDDatatype.XSDdateTime);
            Txn.executeWrite(dsg, () -> {
                dsg.removeGraph(attestation);
                dsg.addGraph(attestation, graph);
                dsg.deleteAny(PENDING, attestation, SINCE, Node.ANY);
                dsg.add(PENDING, attestation, SINCE, time);
            });
        }

        @Override
        public boolean completePending(Node attestation, Graph additions) {
            return Txn.calculateWrite(dsg, () -> {
                if ( !dsg.contains(PENDING, attestation, SINCE, Node.ANY) )
                    return false;
                additions.find().forEach(t -> dsg.add(new Quad(attestation, t)));
                dsg.deleteAny(PENDING, attestation, SINCE, Node.ANY);
                return true;
            });
        }

        @Override
        public Optional<Instant> pendingSince(Node attestation) {
            return Txn.calculateRead(dsg, () -> {
                var it = dsg.find(PENDING, attestation, SINCE, Node.ANY);
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
        public boolean recordKeyActivation(String didKey, Instant at) {
            Node key = NodeFactory.createURI(didKey);
            Node time = NodeFactory.createLiteralDT(DateTimeFormatter.ISO_INSTANT.format(at), XSDDatatype.XSDdateTime);
            return Txn.calculateWrite(dsg, () -> {
                String latest = null;
                Instant latestAt = null;
                for ( var it = dsg.find(KEYS, Node.ANY, ACTIVATED, Node.ANY) ; it.hasNext() ; ) {
                    Quad q = it.next();
                    Instant t = instant(q.getObject());
                    if ( t != null && (latestAt == null || t.isAfter(latestAt)) ) {
                        latestAt = t;
                        latest = q.getSubject().getURI();
                    }
                }
                if ( didKey.equals(latest) )
                    return false;
                dsg.add(KEYS, key, ACTIVATED, time);
                return true;
            });
        }

        @Override
        public Map<String, List<Instant>> keyActivations() {
            return Txn.calculateRead(dsg, () -> {
                Map<String, List<Instant>> out = new TreeMap<>();
                dsg.stream(KEYS, Node.ANY, ACTIVATED, Node.ANY).forEach(q -> {
                    Instant t = instant(q.getObject());
                    if ( t != null && q.getSubject().isURI() )
                        out.computeIfAbsent(q.getSubject().getURI(), k -> new ArrayList<>()).add(t);
                });
                out.values().forEach(Collections::sort);
                return out;
            });
        }

        private static Instant instant(Node n) {
            try {
                return n.isLiteral() ? Instant.parse(n.getLiteralLexicalForm()) : null;
            } catch (RuntimeException ex) {
                return null;
            }
        }

        @Override
        public List<Node> pending() {
            return Txn.calculateRead(dsg, () -> dsg.stream(PENDING, Node.ANY, SINCE, Node.ANY).map(Quad::getSubject).distinct().toList());
        }
    }
}

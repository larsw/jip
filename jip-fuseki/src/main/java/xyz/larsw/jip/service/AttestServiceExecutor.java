package xyz.larsw.jip.service;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import java.util.function.Supplier;

import org.apache.jena.Jena;
import org.apache.jena.graph.Graph;
import org.apache.jena.graph.Node;
import org.apache.jena.query.Query;
import org.apache.jena.query.QueryExecException;
import org.apache.jena.query.ReadWrite;
import org.apache.jena.sparql.ARQConstants;
import org.apache.jena.sparql.algebra.Op;
import org.apache.jena.sparql.algebra.OpAsQuery;
import org.apache.jena.sparql.algebra.OpVars;
import org.apache.jena.sparql.algebra.op.*;
import org.apache.jena.sparql.core.DatasetGraph;
import org.apache.jena.sparql.core.Var;
import org.apache.jena.sparql.engine.ExecutionContext;
import org.apache.jena.sparql.engine.Rename;
import org.apache.jena.sparql.engine.QueryIterator;
import org.apache.jena.sparql.engine.binding.Binding;
import org.apache.jena.sparql.engine.binding.BindingBuilder;
import org.apache.jena.sparql.engine.binding.BindingFactory;
import org.apache.jena.sparql.engine.iterator.QueryIterPlainWrapper;
import org.apache.jena.sparql.engine.iterator.QueryIterSingleton;
import org.apache.jena.sparql.engine.main.QC;
import org.apache.jena.sparql.service.single.ChainingServiceExecutor;
import org.apache.jena.sparql.service.single.ServiceExecutor;
import org.apache.jena.sparql.util.Context;
import org.apache.jena.system.Txn;
import xyz.larsw.jip.JIP;
import xyz.larsw.jip.canon.ResultSetEncoding;
import xyz.larsw.jip.attestation.AttestationBuilder;
import xyz.larsw.jip.attestation.AttestationStore;
import xyz.larsw.jip.attestation.AttestationTimestamps;
import xyz.larsw.jip.attestation.ProvenanceKeys;
import xyz.larsw.jip.attestation.ProvenanceSigner;
import xyz.larsw.jip.attestation.TimestampAuthorities;
import xyz.larsw.jip.version.DataVersion;
import xyz.larsw.jip.version.DataVersionComponent;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Handles {@code SERVICE <urn:x-provenance:attest> { ... }}: evaluates the inner pattern
 * locally, attests its solution sequence and binds the attestation IRI on every row.
 * <ol>
 * <li>Evaluate the inner pattern and read the persistent data version in the same read
 * transaction (the query's own, or a new one if there is none).</li>
 * <li>Materialize the solutions (at most {@code jip:maxSolutions}, default 10,000).</li>
 * <li>Digest: SHA-256 of the RDFC-1.0 canonical {@code rs:} encoding.</li>
 * <li>Build and sign the PROV-O attestation and store it in the attestation store. If TSAs
 * are configured, an RFC 3161 timestamp over the signature is added: in the background by
 * default (the attestation is pending until then), or before storing in sync mode.</li>
 * <li>Return the rows (merged with the incoming binding) with the attestation variable bound.</li>
 * </ol>
 */
public class AttestServiceExecutor implements ChainingServiceExecutor {
    private static final Logger LOG = LoggerFactory.getLogger(AttestServiceExecutor.class);

    public static final int DEFAULT_MAX_SOLUTIONS = 10_000;

    @Override
    public QueryIterator createExecution(OpService opExecute, OpService opOriginal, Binding binding,
                                         ExecutionContext execCxt, ServiceExecutor chain) {
        Node service = opExecute.getService();
        if ( !service.isURI() || !AttestRequest.matches(service.getURI()) )
            return chain.createExecution(opExecute, opOriginal, binding, execCxt);
        try {
            AttestRequest request = AttestRequest.parse(service.getURI());
            return execute(request, opExecute.getSubOp(), binding, execCxt);
        } catch (RuntimeException ex) {
            if ( opExecute.getSilent() ) {
                LOG.warn("SERVICE SILENT <{}>: {}", service.getURI(), ex.getMessage());
                return QueryIterSingleton.create(binding, execCxt);
            }
            throw ex;
        }
    }

    private record Evaluation(long version, List<Binding> rows) {}

    private QueryIterator execute(AttestRequest request, Op inner, Binding parent, ExecutionContext execCxt) {
        Context context = execCxt.getContext();
        DatasetGraph dsg = execCxt.getDataset();
        DataVersionComponent dataVersion = DataVersion.require(context, dsg);
        if ( dsg.isInTransaction() && dsg.transactionMode() == ReadWrite.WRITE )
            throw new QueryExecException("Attest SERVICE cannot run inside a write transaction "
                                         + "(uncommitted changes have no data version)");

        Var attestationVar = request.attestationVar();
        List<Var> visible = OpVars.visibleVars(inner).stream().filter(v -> v.isNamedVar()).toList();
        if ( visible.contains(attestationVar) )
            throw new QueryExecException("Attest SERVICE: ?" + attestationVar.getVarName()
                                         + " is used inside the attested pattern; choose another name with ?var=");
        List<String> variables = visible.stream().map(Var::getVarName).sorted().toList();
        boolean ordered = isOrdered(inner);
        int maxSolutions = maxSolutions(context);

        Instant started = Instant.now();
        Supplier<Evaluation> evaluate = () -> {
            if ( !dataVersion.inTransaction() )
                throw new IllegalStateException("No transaction on the versioned dataset");
            long version = dataVersion.currentVersion();
            List<Binding> rows = new ArrayList<>();
            QueryIterator iter = QC.execute(inner, BindingFactory.root(), execCxt);
            try {
                while ( iter.hasNext() ) {
                    if ( rows.size() >= maxSolutions )
                        throw new QueryExecException("Attested result exceeds " + maxSolutions + " solutions; narrow the query or raise "
                                                     + JIP.symMaxSolutions.getSymbol());
                    rows.add(iter.next());
                }
            } finally {
                iter.close();
            }
            return new Evaluation(version, rows);
        };
        // Data and version must come from the same snapshot.
        Evaluation eval = dsg.isInTransaction() ? evaluate.get() : Txn.calculateRead(dsg, evaluate);

        if ( eval.rows().isEmpty() && !request.emptyRow() )
            return QueryIterPlainWrapper.create(List.<Binding>of().iterator(), execCxt);

        String digest = ResultSetEncoding.digest(variables, eval.rows(), ordered);
        Instant ended = Instant.now();

        UUID attestationId = UUID.randomUUID();
        Node attestationIri = AttestationBuilder.attestationNode(attestationId);
        ProvenanceSigner key = ProvenanceKeys.get();
        AttestationBuilder.Input input = new AttestationBuilder.Input(
                attestationId, dataVersion.databaseId(), dataVersion.datasetIRI().orElse(null), eval.version(),
                variables, ordered, eval.rows().size(), digest,
                patternText(inner), queryText(context), started, ended);
        Graph attestation = AttestationBuilder.buildSigned(input, key, agentLabel());
        storeWithTimestamp(attestation, attestationIri, context);
        LOG.info("Attested {} solution(s) at database {} v{} -> {}", eval.rows().size(), dataVersion.databaseId(),
                 eval.version(), attestationIri.getURI());

        List<Binding> out = new ArrayList<>(Math.max(1, eval.rows().size()));
        if ( eval.rows().isEmpty() ) {
            out.add(BindingFactory.binding(parent, attestationVar, attestationIri));
        } else {
            for ( Binding row : eval.rows() ) {
                Binding merged = merge(parent, row, visible, attestationVar, attestationIri);
                if ( merged != null )
                    out.add(merged);
            }
        }
        return QueryIterPlainWrapper.create(out.iterator(), execCxt);
    }

    /**
     * Store the attestation, with an RFC 3161 timestamp over its signature if timestamp
     * authorities are configured.
     * <ul>
     * <li>No TSA: store it as it is.</li>
     * <li>Async (default): store it as pending and let the background worker add the timestamp;
     * the query does not wait.</li>
     * <li>Sync: fetch the timestamp first. With the {@code required} policy, no token means no
     * attestation.</li>
     * </ul>
     */
    private static void storeWithTimestamp(Graph attestation, Node attestationIri, Context context) {
        AttestationStore store = AttestationStore.fromContext(context);
        Optional<TimestampAuthorities> tsa;
        try {
            tsa = TimestampAuthorities.fromContext(context);
        } catch (IllegalArgumentException ex) {
            throw new QueryExecException("Bad timestamp configuration: " + ex.getMessage(), ex);
        }
        if ( tsa.isEmpty() ) {
            store.store(attestationIri, attestation);
            return;
        }
        if ( tsa.get().mode() == TimestampAuthorities.Mode.ASYNC ) {
            Instant now = Instant.now();
            store.storePending(attestationIri, attestation, now);
            tsa.get().submit(store, attestationIri, now);
            return;
        }
        Optional<TimestampAuthorities.Stamp> stamp = tsa.get().stamp(AttestationTimestamps.messageImprint(attestation, attestationIri));
        if ( stamp.isPresent() ) {
            AttestationTimestamps.attach(attestation, attestationIri, stamp.get().token(), stamp.get().authority().toString());
        } else if ( tsa.get().policy() == TimestampAuthorities.Policy.REQUIRED ) {
            throw new QueryExecException("No timestamp authority answered " + tsa.get().authorities()
                                         + " and a timestamp is required (" + JIP.symTimestampPolicy.getSymbol() + ")");
        } else {
            LOG.warn("Attestation {} issued without an RFC 3161 timestamp", attestationIri.getURI());
        }
        store.store(attestationIri, attestation);
    }

    /** Parent + the row's named visible variables + the attestation; null if incompatible. */
    private static Binding merge(Binding parent, Binding row, List<Var> visible, Var attestationVar, Node attestationIri) {
        BindingBuilder b = BindingBuilder.create(parent);
        for ( Var v : visible ) {
            Node n = row.get(v);
            if ( n == null )
                continue;
            Node existing = parent.get(v);
            if ( existing != null ) {
                if ( !existing.equals(n) )
                    return null;
                continue;
            }
            b.add(v, n);
        }
        b.add(attestationVar, attestationIri);
        return b.build();
    }

    /** ORDER BY (or TopN) under the solution modifiers at the top of the inner pattern. */
    static boolean isOrdered(Op op) {
        Op o = op;
        while ( true ) {
            if ( o instanceof OpOrder || o instanceof OpTopN )
                return true;
            if ( o instanceof OpSlice || o instanceof OpDistinct || o instanceof OpReduced || o instanceof OpProject
                 || o instanceof OpExtend || o instanceof OpAssign )
                o = ((Op1)o).getSubOp();
            else
                return false;
        }
    }

    static int maxSolutions(Context context) {
        Object v = context.get(JIP.symMaxSolutions);
        if ( v == null )
            return DEFAULT_MAX_SOLUTIONS;
        try {
            int n = v instanceof Number num ? num.intValue() : Integer.parseInt(v.toString().strip());
            return n > 0 ? n : DEFAULT_MAX_SOLUTIONS;
        } catch (NumberFormatException ex) {
            LOG.warn("Bad {} value '{}', using {}", JIP.symMaxSolutions.getSymbol(), v, DEFAULT_MAX_SOLUTIONS);
            return DEFAULT_MAX_SOLUTIONS;
        }
    }

    private static String patternText(Op inner) {
        try {
            // Undo the algebra's scope renaming (?/p) so the text reads like the query.
            return OpAsQuery.asQuery(Rename.reverseVarRename(inner, true)).toString().strip();
        } catch (RuntimeException ex) {
            return inner.toString().strip();
        }
    }

    private static String queryText(Context context) {
        Object q = context.get(ARQConstants.sysCurrentQuery);
        return q instanceof Query query ? query.toString().strip() : null;
    }

    static String agentLabel() {
        String v = AttestServiceExecutor.class.getPackage().getImplementationVersion();
        return "jena-intrinsic-provenance " + (v == null ? "dev" : v) + " on Apache Jena " + Jena.VERSION;
    }
}

package xyz.larsw.jip.version;

import java.nio.file.Path;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

import org.apache.jena.dboe.base.file.Location;
import org.apache.jena.dboe.transaction.txn.TransactionCoordinator;
import org.apache.jena.dboe.transaction.txn.TransactionInfo;
import org.apache.jena.query.QueryExecException;
import org.apache.jena.sparql.core.DatasetGraph;
import org.apache.jena.sparql.core.DatasetGraphWrapper;
import org.apache.jena.sparql.util.Context;
import org.apache.jena.system.Txn;
import org.apache.jena.tdb2.store.DatasetGraphSwitchable;
import org.apache.jena.tdb2.store.DatasetGraphTDB;
import org.apache.jena.tdb2.sys.TDBInternal;
import xyz.larsw.jip.JIP;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Attach the persistent data version to a TDB2 database and find it again.
 * <p>
 * Normally used through the {@code jip:VersionedDatasetTDB2} assembler, which also runs
 * {@link PreOpenJournalRecovery} before the database is opened.
 */
public final class DataVersion {
    private static final Logger LOG = LoggerFactory.getLogger(DataVersion.class);

    private DataVersion() {}

    /** Attached components by database container (stable across compaction). */
    private static final Map<DatasetGraphSwitchable, DataVersionComponent> byContainer = new ConcurrentHashMap<>();
    /** On-disk databases with an attached component, by normalized directory path. */
    private static final Map<String, DataVersionComponent> byDirectory = new ConcurrentHashMap<>();

    /** True if a component is already attached for the on-disk database at this location. */
    public static boolean isAttached(Location location) {
        return !location.isMem() && byDirectory.containsKey(directoryKey(location));
    }

    /**
     * Attach the data version component to a TDB2 database (idempotent).
     *
     * @param dsg        a TDB2 database container (as returned by {@code DatabaseMgr.connectDatasetGraph})
     * @param datasetIRI optional IRI naming the logical dataset; may be null
     */
    public static synchronized DataVersionComponent attach(DatasetGraph dsg, String datasetIRI) {
        DatasetGraphSwitchable container = unwrapToContainer(dsg);
        if ( container == null )
            throw new IllegalArgumentException("Not a TDB2 database: " + dsg.getClass().getName());

        DataVersionComponent existing = byContainer.get(container);
        if ( existing != null ) {
            if ( datasetIRI != null && !existing.datasetIRI().map(datasetIRI::equals).orElse(false) )
                LOG.warn("Data version already attached to {} with datasetIRI {}; ignoring {}",
                         container.getLocation(), existing.datasetIRI().orElse("(none)"), datasetIRI);
            return existing;
        }

        Location location = container.getLocation();
        DataVersionComponent component;
        if ( location.isMem() ) {
            component = new DataVersionComponent(UUID.randomUUID(), datasetIRI, null, 0L);
        } else {
            DataVersionStateFile stateFile = new DataVersionStateFile(Path.of(location.getDirectoryPath()));
            DataVersionStateFile.State state = stateFile.readOrCreate();
            component = new DataVersionComponent(state.databaseId(), datasetIRI, stateFile, state.version());
        }

        TransactionCoordinator coordinator = TDBInternal.getTransactionCoordinator(container);
        // External components move to the new coordinator when the database is compacted.
        coordinator.modifyConfig(() -> coordinator.addExternal(component));
        container.getContext().set(JIP.symDataVersion, component);

        byContainer.put(container, component);
        if ( !location.isMem() )
            byDirectory.put(directoryKey(location), component);
        LOG.info("Persistent data version attached: {} database={} version={}",
                 location.isMem() ? "(memory)" : location.getDirectoryPath(), component.databaseId(),
                 component.committedVersion());
        return component;
    }

    /** Find the component for a dataset (unwrapping dataset wrappers). */
    public static Optional<DataVersionComponent> find(DatasetGraph dsg) {
        DatasetGraph d = dsg;
        for ( int depth = 0 ; d != null && depth < 32 ; depth++ ) {
            Context cxt = d.getContext();
            if ( cxt != null && cxt.get(JIP.symDataVersion) instanceof DataVersionComponent c )
                return Optional.of(c);
            // ARQ evaluates against the storage (DatasetGraphTDB), not the switchable container.
            // The coordinator's external components are the source of truth: they are carried
            // over on compaction while the storage's context is not.
            if ( d instanceof DatasetGraphSwitchable || d instanceof DatasetGraphTDB )
                return fromCoordinator(d);
            if ( d instanceof DatasetGraphWrapper w )
                d = w.getWrapped();
            else
                break;
        }
        return Optional.empty();
    }

    private static Optional<DataVersionComponent> fromCoordinator(DatasetGraph tdb) {
        TransactionCoordinator coordinator = TDBInternal.getTransactionCoordinator(tdb);
        if ( coordinator == null )
            return Optional.empty();
        return coordinator.listExternals().stream()
                .filter(DataVersionComponent.class::isInstance)
                .map(DataVersionComponent.class::cast)
                .findFirst();
    }

    /** Find the component for a query execution: the dataset first, then the execution context. */
    public static Optional<DataVersionComponent> find(Context context, DatasetGraph dsg) {
        Optional<DataVersionComponent> c = dsg == null ? Optional.empty() : find(dsg);
        if ( c.isPresent() )
            return c;
        if ( context != null && context.get(JIP.symDataVersion) instanceof DataVersionComponent cc )
            return Optional.of(cc);
        return Optional.empty();
    }

    /** As {@link #find(Context, DatasetGraph)}, failing the query if there is no data version. */
    public static DataVersionComponent require(Context context, DatasetGraph dsg) {
        return find(context, dsg).orElseThrow(() -> new QueryExecException(
                "Dataset has no persistent data version: configure it as " + JIP.VersionedDatasetTDB2.getURI()));
    }

    /**
     * TDB2's internal, volatile data version ({@code TransactionCoordinator.dataVersion}) for the
     * current thread's transaction, or from a short read transaction if there is none.
     * Restarts at 0 on every JVM start.
     */
    public static long tdbInternalVersion(DatasetGraph dsg) {
        DatasetGraph tdb = unwrapToTDB(dsg);
        if ( tdb == null )
            throw new QueryExecException("Not a TDB2 dataset");
        Long inTxn = threadTdbVersion(tdb);
        if ( inTxn != null )
            return inTxn;
        return Txn.calculateRead(tdb, () -> {
            Long v = threadTdbVersion(tdb);
            if ( v == null )
                throw new IllegalStateException("No TDB2 transaction after begin");
            return v;
        });
    }

    private static Long threadTdbVersion(DatasetGraph tdb) {
        DatasetGraphTDB storage = TDBInternal.getDatasetGraphTDB(tdb);
        if ( storage == null )
            return null;
        TransactionInfo info = storage.getTxnSystem().getTransactionInfo();
        return info == null ? null : info.getDataVersion();
    }

    /** Unwrap to a TDB2 container ({@link DatasetGraphSwitchable}) or storage ({@link DatasetGraphTDB}). */
    private static DatasetGraph unwrapToTDB(DatasetGraph dsg) {
        DatasetGraph d = dsg;
        for ( int depth = 0 ; d != null && depth < 32 ; depth++ ) {
            if ( d instanceof DatasetGraphSwitchable || d instanceof DatasetGraphTDB )
                return d;
            if ( d instanceof DatasetGraphWrapper w )
                d = w.getWrapped();
            else
                return null;
        }
        return null;
    }

    private static DatasetGraphSwitchable unwrapToContainer(DatasetGraph dsg) {
        return unwrapToTDB(dsg) instanceof DatasetGraphSwitchable s ? s : null;
    }

    private static String directoryKey(Location location) {
        return Path.of(location.getDirectoryPath()).toAbsolutePath().normalize().toString();
    }

    /** Testing only: forget attached components (does not detach them). */
    public static synchronized void resetForTesting() {
        byContainer.clear();
        byDirectory.clear();
    }
}

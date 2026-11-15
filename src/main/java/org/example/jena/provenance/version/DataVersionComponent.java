package org.example.jena.provenance.version;

import java.nio.ByteBuffer;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicLong;

import org.apache.jena.dboe.transaction.txn.ComponentId;
import org.apache.jena.dboe.transaction.txn.TransactionException;
import org.apache.jena.dboe.transaction.txn.TransactionalComponentExternal;
import org.apache.jena.dboe.transaction.txn.TxnId;
import org.apache.jena.query.ReadWrite;

/**
 * A DBOE transactional component holding a persistent, monotonically increasing data version.
 * <p>
 * Registered on a TDB2 {@code TransactionCoordinator} as an <em>external</em> component, so it
 * is carried over to the new coordinator when the database is compacted.
 * <ul>
 * <li>{@code _commitPrepare}: writes a REDO entry (format, version+1) to TDB2's journal; it
 * becomes durable under the same COMMIT record as the data.</li>
 * <li>{@code _commit} (after the commit point): atomically rewrites the state file.</li>
 * <li>{@code _commitEnd}: publishes the new value to new transactions.</li>
 * </ul>
 * Every committed write transaction bumps the version (also ones without changes); aborts and
 * reads never do. Begin, commit and commitEnd all run under the coordinator lock, so a
 * transaction's view of the version is consistent with its view of the data.
 * <p>
 * Crash window: if the process dies after the journal commit point but before the state file
 * is written, the REDO entry is still in the journal. Because this component is registered
 * after TDB2 has opened (and replayed) the journal, the replay is done by
 * {@link PreOpenJournalRecovery} before the database is opened.
 */
public final class DataVersionComponent extends TransactionalComponentExternal<DataVersionComponent.TxnVersion> {

    /** "PROV" in ASCII. TDB2's own components use ids 1..51. */
    public static final int COMPONENT_INDEX = 0x50524F56;
    /** Version of the REDO record layout: int format, long version. */
    static final int REDO_FORMAT = 1;
    private static final UUID BASE = UUID.fromString("6a1f6c2e-0000-4000-8000-50524f560000");

    /** Per-transaction state. */
    static final class TxnVersion {
        final long start;
        long next = -1;

        TxnVersion(long start) {
            this.start = start;
        }
    }

    private final UUID databaseId;
    private final String datasetIRI;
    private final DataVersionStateFile stateFile;   // null for in-memory databases
    private final AtomicLong committed;

    DataVersionComponent(UUID databaseId, String datasetIRI, DataVersionStateFile stateFile, long initialVersion) {
        super(componentId());
        this.databaseId = databaseId;
        this.datasetIRI = datasetIRI;
        this.stateFile = stateFile;
        this.committed = new AtomicLong(initialVersion);
    }

    public static ComponentId componentId() {
        return ComponentId.alloc("jip-data-version", BASE, COMPONENT_INDEX);
    }

    public UUID databaseId() {
        return databaseId;
    }

    /** The configured logical dataset IRI, if any. */
    public Optional<String> datasetIRI() {
        return Optional.ofNullable(datasetIRI);
    }

    /** True if the version is persisted (on-disk database). */
    public boolean isPersistent() {
        return stateFile != null;
    }

    /** The last committed version (outside any transaction). */
    public long committedVersion() {
        return committed.get();
    }

    /**
     * The version of the snapshot seen by the current thread's transaction on this database.
     * For a write transaction this is the version it started from.
     *
     * @throws TransactionException if the current thread has no transaction on this database.
     */
    public long currentVersion() {
        TxnVersion state = getDataState();
        if ( state == null )
            throw new TransactionException("Not in a transaction on this dataset");
        return state.start;
    }

    /** True if the current thread is in a transaction on this database. */
    public boolean inTransaction() {
        return getDataState() != null;
    }

    // ---- Recovery: only called if the component is registered before the coordinator starts
    // (embedded use). Fuseki/assembler use goes through PreOpenJournalRecovery instead.

    private long recovered = -1;

    @Override
    public void startRecovery() {
        recovered = -1;
    }

    @Override
    public void recover(ByteBuffer ref) {
        recovered = Math.max(recovered, decodeRedo(ref));
    }

    @Override
    public void finishRecovery() {
        if ( recovered > committed.get() ) {
            if ( stateFile != null )
                stateFile.write(new DataVersionStateFile.State(databaseId, recovered));
            committed.set(recovered);
        }
        recovered = -1;
    }

    @Override
    public void cleanStart() {}

    // ---- Transaction lifecycle

    @Override
    protected TxnVersion _begin(ReadWrite readWrite, TxnId txnId) {
        long v = committed.get();
        RequestVersionTracker.observeBegin(this, v);
        return new TxnVersion(v);
    }

    @Override
    protected TxnVersion _promote(TxnId txnId, TxnVersion oldState) {
        // The coordinator has decided promotion is legal; build on the latest committed state.
        return new TxnVersion(committed.get());
    }

    @Override
    protected ByteBuffer _commitPrepare(TxnId txnId, TxnVersion state) {
        if ( !isWriteTxn() )
            return null;
        // Single writer: committed cannot change between here and commitEnd.
        state.next = committed.get() + 1;
        return encodeRedo(state.next);
    }

    @Override
    protected void _commit(TxnId txnId, TxnVersion state) {
        if ( !isWriteTxn() )
            return;
        // After the journal commit point. If this fails the journal is not truncated and the
        // entry is replayed on next start.
        if ( stateFile != null )
            stateFile.write(new DataVersionStateFile.State(databaseId, state.next));
    }

    @Override
    protected void _commitEnd(TxnId txnId, TxnVersion state) {
        if ( !isWriteTxn() )
            return;
        committed.set(state.next);
        RequestVersionTracker.observeCommit(this, state.next);
    }

    @Override
    protected void _abort(TxnId txnId, TxnVersion state) {
        if ( isWriteTxn() )
            RequestVersionTracker.observeAbort(this);
    }

    @Override
    protected void _complete(TxnId txnId, TxnVersion state) {}

    @Override
    protected void _shutdown() {
        // Called when an old coordinator shuts down after compaction: the same component
        // instance continues on the new coordinator, so nothing is released here.
    }

    // ---- REDO record

    static ByteBuffer encodeRedo(long version) {
        ByteBuffer bb = ByteBuffer.allocate(Integer.BYTES + Long.BYTES);
        bb.putInt(REDO_FORMAT).putLong(version).flip();
        return bb;
    }

    static long decodeRedo(ByteBuffer ref) {
        ByteBuffer bb = ref.duplicate();
        bb.rewind();
        int format = bb.getInt();
        if ( format != REDO_FORMAT )
            throw new IllegalStateException("Unknown data version REDO format: " + format);
        return bb.getLong();
    }

    @Override
    public String toString() {
        return "DataVersionComponent[" + databaseId + " v" + committed.get() + "]";
    }
}

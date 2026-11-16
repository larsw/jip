package org.example.jena.provenance.version;

import static org.junit.jupiter.api.Assertions.*;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.atomic.AtomicLong;

import org.apache.jena.dboe.base.file.Location;
import org.apache.jena.dboe.transaction.txn.journal.Journal;
import org.apache.jena.dboe.transaction.txn.journal.JournalEntry;
import org.apache.jena.dboe.transaction.txn.journal.JournalEntryType;
import org.apache.jena.query.QueryExecException;
import org.apache.jena.query.TxnType;
import org.apache.jena.sparql.core.DatasetGraph;
import org.apache.jena.sparql.core.DatasetGraphFactory;
import org.apache.jena.sparql.engine.binding.Binding;
import org.apache.jena.sparql.exec.QueryExec;
import org.apache.jena.sparql.sse.SSE;
import org.apache.jena.system.Txn;
import org.apache.jena.tdb2.DatabaseMgr;
import org.apache.jena.tdb2.sys.DatabaseOps;
import org.apache.jena.tdb2.sys.TDBInternal;
import org.example.jena.provenance.TestLib;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class DataVersionTest {

    @TempDir
    Path tmp;

    @AfterEach
    void cleanup() {
        TDBInternal.reset();
        DataVersion.resetForTesting();
    }

    static DatasetGraph assemble(String location) {
        return TestLib.assembleVersioned(location);
    }

    static void write(DatasetGraph dsg, String quad) {
        Txn.executeWrite(dsg, () -> dsg.add(SSE.parseQuad(quad)));
    }

    static long version(DatasetGraph dsg) {
        return DataVersion.find(dsg).orElseThrow().committedVersion();
    }

    /** Simulate a process restart for an on-disk database. */
    static void restart(DatasetGraph dsg) {
        TDBInternal.expel(dsg);
        DataVersion.resetForTesting();
    }

    @Test
    void bumpsOnCommittedWritesOnly() {
        DatasetGraph dsg = assemble("--mem--");
        assertEquals(0, version(dsg));

        write(dsg, "(_ :s :p 1)");
        assertEquals(1, version(dsg));

        Txn.executeRead(dsg, () -> dsg.find().forEachRemaining(q -> {}));
        assertEquals(1, version(dsg), "read transactions do not bump");

        dsg.begin(TxnType.WRITE);
        dsg.add(SSE.parseQuad("(_ :s :p 2)"));
        dsg.abort();
        dsg.end();
        assertEquals(1, version(dsg), "aborts do not bump");

        Txn.executeWrite(dsg, () -> {});
        assertEquals(2, version(dsg), "empty write transactions bump (every committed write)");
    }

    @Test
    void readersSeeTheirSnapshotVersion() throws Exception {
        DatasetGraph dsg = assemble("--mem--");
        write(dsg, "(_ :s :p 1)");
        DataVersionComponent c = DataVersion.find(dsg).orElseThrow();

        CountDownLatch readerStarted = new CountDownLatch(1);
        CountDownLatch writerDone = new CountDownLatch(1);
        AtomicLong seenBefore = new AtomicLong(-1);
        AtomicLong seenAfter = new AtomicLong(-1);
        AtomicLong queryAfter = new AtomicLong(-1);

        Thread reader = new Thread(() -> Txn.executeRead(dsg, () -> {
            seenBefore.set(c.currentVersion());
            readerStarted.countDown();
            try { writerDone.await(); } catch (InterruptedException e) { Thread.currentThread().interrupt(); }
            seenAfter.set(c.currentVersion());
            queryAfter.set(queryVersions(dsg)[0]);
        }));
        reader.start();
        readerStarted.await();
        write(dsg, "(_ :s :p 2)");
        writerDone.countDown();
        reader.join();

        assertEquals(1, seenBefore.get());
        assertEquals(1, seenAfter.get(), "a reader keeps its snapshot version");
        assertEquals(1, queryAfter.get(), "jip:dataVersion() reports the snapshot version");
        assertEquals(2, c.committedVersion());
    }

    @Test
    void functionsReportPersistentAndInternalVersions() {
        DatasetGraph dsg = assemble(tmp.resolve("db").toString());
        write(dsg, "(_ :s :p 1)");
        write(dsg, "(_ :s :p 2)");
        long[] v = queryVersions(dsg);
        assertEquals(2, v[0]);
        assertEquals(2, v[1]);

        // After a restart, TDB2's internal counter starts again at 0; the persistent one does not.
        restart(dsg);
        DatasetGraph dsg2 = assemble(tmp.resolve("db").toString());
        write(dsg2, "(_ :s :p 3)");
        long[] v2 = queryVersions(dsg2);
        assertEquals(3, v2[0], "persistent version continues");
        assertEquals(1, v2[1], "TDB2 internal version restarted");
    }

    @Test
    void functionFailsOnUnversionedDataset() {
        DatasetGraph plain = DatasetGraphFactory.createTxnMem();
        assertThrows(QueryExecException.class, () -> queryVersions(plain));
    }

    @Test
    void persistsAcrossRestartWithStableIdentity() {
        String dir = tmp.resolve("db").toString();
        DatasetGraph dsg = assemble(dir);
        UUID id = DataVersion.find(dsg).orElseThrow().databaseId();
        for ( int i = 0 ; i < 5 ; i++ )
            write(dsg, "(_ :s :p " + i + ")");
        assertEquals(5, version(dsg));
        restart(dsg);

        DatasetGraph dsg2 = assemble(dir);
        DataVersionComponent c2 = DataVersion.find(dsg2).orElseThrow();
        assertEquals(5, c2.committedVersion());
        assertEquals(id, c2.databaseId());
        assertEquals("https://example.org/ds", c2.datasetIRI().orElseThrow());

        // persistent - internal is constant within one process
        long base = c2.committedVersion() - DataVersion.tdbInternalVersion(dsg2);
        for ( int i = 0 ; i < 3 ; i++ ) {
            write(dsg2, "(_ :s :q " + i + ")");
            assertEquals(base, c2.committedVersion() - DataVersion.tdbInternalVersion(dsg2));
        }
    }

    @Test
    void survivesCompaction() {
        String dir = tmp.resolve("db").toString();
        DatasetGraph dsg = assemble(dir);
        write(dsg, "(_ :s :p 1)");
        write(dsg, "(_ :s :p 2)");
        var coordinatorBefore = TDBInternal.getTransactionCoordinator(dsg);

        DatabaseMgr.compact(dsg, true);
        assertNotSame(coordinatorBefore, TDBInternal.getTransactionCoordinator(dsg), "compaction switches coordinator");
        assertTrue(Files.exists(tmp.resolve("db").resolve("Data-0002")));

        write(dsg, "(_ :s :p 3)");
        assertEquals(3, version(dsg), "component carried to the new coordinator");
        assertEquals(3, queryVersions(dsg)[0]);

        restart(dsg);
        DatasetGraph dsg2 = assemble(dir);
        assertEquals(3, version(dsg2));
    }

    @Test
    void replaysCommittedJournalEntryBeforeOpen() {
        Path dbDir = tmp.resolve("db");
        DatasetGraph dsg = assemble(dbDir.toString());
        write(dsg, "(_ :s :p 1)");
        write(dsg, "(_ :s :p 2)");
        restart(dsg);
        assertEquals(2, new DataVersionStateFile(dbDir).read().orElseThrow().version());

        // Simulate a crash after the journal commit point of a third write transaction
        // but before the state file was rewritten: REDO(v3) + COMMIT left in the journal.
        // A later uncommitted entry (crash before commit point) must be ignored.
        Location storage = Location.create(DatabaseOps.findStorageLocation(dbDir).toString());
        Journal journal = Journal.create(storage);
        journal.write(JournalEntryType.REDO, DataVersionComponent.componentId(), DataVersionComponent.encodeRedo(3));
        journal.writeJournal(JournalEntry.COMMIT);
        journal.write(JournalEntryType.REDO, DataVersionComponent.componentId(), DataVersionComponent.encodeRedo(4));
        journal.sync();
        journal.close();

        DatasetGraph dsg2 = assemble(dbDir.toString());
        assertEquals(3, version(dsg2), "committed journal entry replayed; uncommitted one ignored");
        write(dsg2, "(_ :s :p 3)");
        assertEquals(4, version(dsg2));
    }

    /** [jip:dataVersion(), jip:tdbDataVersion()] via SPARQL. */
    static long[] queryVersions(DatasetGraph dsg) {
        String q = """
                PREFIX jip: <https://larsw.xyz/jip/>
                SELECT (jip:dataVersion() AS ?v) (jip:tdbDataVersion() AS ?t) {}
                """;
        try ( QueryExec qExec = QueryExec.dataset(dsg).query(q).build() ) {
            Binding row = qExec.select().next();
            assertNotNull(row.get("v"), "jip:dataVersion() unbound");
            assertNotNull(row.get("t"), "jip:tdbDataVersion() unbound");
            return new long[] { Long.parseLong(row.get("v").getLiteralLexicalForm()),
                                Long.parseLong(row.get("t").getLiteralLexicalForm()) };
        }
    }
}

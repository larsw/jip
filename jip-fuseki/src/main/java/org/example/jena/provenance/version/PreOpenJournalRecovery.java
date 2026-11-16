package org.example.jena.provenance.version;

import java.nio.file.Path;
import java.util.Iterator;
import java.util.Optional;
import java.util.OptionalLong;
import java.util.UUID;

import org.apache.jena.dboe.base.file.Location;
import org.apache.jena.dboe.transaction.txn.ComponentId;
import org.apache.jena.dboe.transaction.txn.journal.Journal;
import org.apache.jena.dboe.transaction.txn.journal.JournalEntry;
import org.apache.jena.tdb2.sys.DatabaseOps;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Replays committed data-version REDO entries from a TDB2 journal <em>before</em> TDB2 opens
 * the database.
 * <p>
 * TDB2 replays its journal when the database is opened and drops entries for components that
 * are not registered at that point ("No component for ..."). The data version component can
 * only be attached after the database is open, so its share of the replay is done here: scan
 * {@code Data-NNNN/journal.jrnl}, take the version from the last REDO entry that is followed by
 * a COMMIT, and advance the state file if it is behind.
 * <p>
 * The journal is only read, never modified; TDB2's own recovery runs afterwards as usual.
 */
public final class PreOpenJournalRecovery {
    private static final Logger LOG = LoggerFactory.getLogger(PreOpenJournalRecovery.class);

    private PreOpenJournalRecovery() {}

    /**
     * Recover the data version for the TDB2 database in {@code databaseDirectory}.
     *
     * @return the recovered version if the state file was advanced, otherwise empty.
     */
    public static OptionalLong recover(Path databaseDirectory) {
        OptionalLong fromJournal = lastCommittedVersion(databaseDirectory);
        if ( fromJournal.isEmpty() )
            return OptionalLong.empty();
        long journalVersion = fromJournal.getAsLong();

        DataVersionStateFile stateFile = new DataVersionStateFile(databaseDirectory);
        Optional<DataVersionStateFile.State> state = stateFile.read();
        if ( state.isEmpty() ) {
            // The state file is created when the component is first attached, so a committed
            // entry without a state file means it was deleted. Keep monotonicity from the journal.
            UUID id = UUID.randomUUID();
            LOG.warn("Data version state file missing in {}; recreating at v{} with new database id {}",
                     databaseDirectory, journalVersion, id);
            stateFile.write(new DataVersionStateFile.State(id, journalVersion));
            return OptionalLong.of(journalVersion);
        }
        long fileVersion = state.get().version();
        if ( journalVersion <= fileVersion )
            return OptionalLong.empty();
        LOG.warn("Recovered data version from journal for {}: v{} -> v{}", databaseDirectory, fileVersion, journalVersion);
        stateFile.write(new DataVersionStateFile.State(state.get().databaseId(), journalVersion));
        return OptionalLong.of(journalVersion);
    }

    /** The version in the last committed data-version REDO entry of the journal, if any. */
    static OptionalLong lastCommittedVersion(Path databaseDirectory) {
        Path storage = DatabaseOps.findStorageLocation(databaseDirectory);
        if ( storage == null )
            return OptionalLong.empty();
        Location location = Location.create(storage.toString());
        if ( !Journal.exists(location) )
            return OptionalLong.empty();

        ComponentId ours = DataVersionComponent.componentId();
        long lastCommitted = -1;
        Long pending = null;
        Journal journal = Journal.create(location);
        try {
            if ( journal.isEmpty() )
                return OptionalLong.empty();
            Iterator<JournalEntry> iter = journal.entries();
            while ( iter.hasNext() ) {
                JournalEntry entry = iter.next();
                switch (entry.getType()) {
                    case REDO -> {
                        if ( ours.equals(entry.getComponentId()) )
                            pending = DataVersionComponent.decodeRedo(entry.getByteBuffer());
                    }
                    case COMMIT -> {
                        if ( pending != null )
                            lastCommitted = Math.max(lastCommitted, pending);
                        pending = null;
                    }
                    case ABORT -> pending = null;
                    case UNDO -> {}
                }
            }
        } catch (RuntimeException ex) {
            // A torn tail (crash while writing the journal) cannot hold a COMMIT for its entries.
            LOG.warn("Stopped reading journal at {}: {}", location, ex.getMessage());
        } finally {
            journal.close();
        }
        return lastCommitted < 0 ? OptionalLong.empty() : OptionalLong.of(lastCommitted);
    }
}

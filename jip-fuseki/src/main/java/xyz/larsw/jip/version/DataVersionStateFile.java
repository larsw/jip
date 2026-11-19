package xyz.larsw.jip.version;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

/**
 * The on-disk state of the persistent data version: database id and last committed version.
 * <p>
 * Lives in the TDB2 database root directory (next to {@code Data-NNNN/}), so it is not
 * affected by compaction. Writes are atomic: temp file, fsync, rename, fsync directory.
 */
public final class DataVersionStateFile {

    public static final String FILENAME = "jip-data-version.properties";
    private static final int FORMAT = 1;

    /** Database identity and last committed version. */
    public record State(UUID databaseId, long version) {}

    private final Path file;

    public DataVersionStateFile(Path databaseDirectory) {
        this.file = databaseDirectory.resolve(FILENAME);
    }

    public Path path() {
        return file;
    }

    public Optional<State> read() {
        if ( !Files.exists(file) )
            return Optional.empty();
        try {
            Map<String, String> kv = new HashMap<>();
            for ( String line : Files.readAllLines(file, StandardCharsets.UTF_8) ) {
                line = line.strip();
                if ( line.isEmpty() || line.startsWith("#") )
                    continue;
                int idx = line.indexOf('=');
                if ( idx > 0 )
                    kv.put(line.substring(0, idx).strip(), line.substring(idx + 1).strip());
            }
            String format = kv.get("format");
            if ( format == null || Integer.parseInt(format) != FORMAT )
                throw new IllegalStateException("Unsupported data version state format in " + file + ": " + format);
            UUID id = UUID.fromString(require(kv, "databaseId"));
            long version = Long.parseLong(require(kv, "version"));
            if ( version < 0 )
                throw new IllegalStateException("Negative version in " + file);
            return Optional.of(new State(id, version));
        } catch (IOException ex) {
            throw new UncheckedIOException("Failed to read " + file, ex);
        }
    }

    /** Read the state, creating it (new database id, version 0) if it does not exist. */
    public State readOrCreate() {
        Optional<State> existing = read();
        if ( existing.isPresent() )
            return existing.get();
        State initial = new State(UUID.randomUUID(), 0L);
        write(initial);
        return initial;
    }

    /** Atomically replace the state file and force it to disk. */
    public void write(State state) {
        String content = """
                # jena-intrinsic-provenance: persistent data version. Do not edit.
                format=%d
                databaseId=%s
                version=%d
                """.formatted(FORMAT, state.databaseId(), state.version());
        Path tmp = file.resolveSibling(FILENAME + ".tmp");
        try {
            Files.createDirectories(file.getParent());
            try ( FileChannel ch = FileChannel.open(tmp, StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING,
                                                    StandardOpenOption.WRITE) ) {
                ByteBuffer bb = ByteBuffer.wrap(content.getBytes(StandardCharsets.UTF_8));
                while ( bb.hasRemaining() )
                    ch.write(bb);
                ch.force(true);
            }
            Files.move(tmp, file, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
            fsyncDirectory(file.getParent());
        } catch (IOException ex) {
            throw new UncheckedIOException("Failed to write " + file, ex);
        }
    }

    private static void fsyncDirectory(Path dir) {
        // Makes the rename durable on POSIX file systems; not supported everywhere.
        try ( FileChannel ch = FileChannel.open(dir, StandardOpenOption.READ) ) {
            ch.force(true);
        } catch (IOException | UnsupportedOperationException ignored) {}
    }

    private String require(Map<String, String> kv, String key) {
        String v = kv.get(key);
        if ( v == null )
            throw new IllegalStateException("Missing '" + key + "' in " + file);
        return v;
    }
}

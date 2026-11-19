package xyz.larsw.jip.cert;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;
import java.util.Optional;
import java.util.function.Function;

/**
 * Where signer providers read their settings: each setting has an environment variable name
 * and a system property name; the environment variable wins. Tests and embedded use can supply
 * a map instead (keyed by the environment variable name).
 */
public final class SignerSettings {
    private final Function<String, String> env;
    private final Function<String, String> props;

    private SignerSettings(Function<String, String> env, Function<String, String> props) {
        this.env = env;
        this.props = props;
    }

    /** Environment variables and system properties. */
    public static SignerSettings system() {
        return new SignerSettings(System::getenv, System::getProperty);
    }

    /** Fixed values keyed by environment variable name (tests, embedded use). */
    public static SignerSettings of(Map<String, String> values) {
        return new SignerSettings(values::get, k -> null);
    }

    /** The value, if set and not blank. */
    public Optional<String> get(String envName, String propName) {
        String v = env.apply(envName);
        if ( v == null || v.isBlank() )
            v = propName == null ? null : props.apply(propName);
        return v == null || v.isBlank() ? Optional.empty() : Optional.of(v.strip());
    }

    /**
     * A secret given directly ({@code envName}) or as a file ({@code fileEnvName}, as with
     * Docker secrets). The file's content is used without its trailing newline.
     */
    public Optional<char[]> secret(String envName, String propName, String fileEnvName, String filePropName) {
        Optional<String> file = get(fileEnvName, filePropName);
        if ( file.isPresent() ) {
            try {
                String s = Files.readString(Path.of(file.get()), StandardCharsets.UTF_8);
                return Optional.of(s.replaceAll("[\\r\\n]+$", "").toCharArray());
            } catch (IOException ex) {
                throw new UncheckedIOException("Cannot read " + file.get(), ex);
            }
        }
        String v = env.apply(envName);
        if ( v == null || v.isEmpty() )
            v = propName == null ? null : props.apply(propName);
        return v == null || v.isEmpty() ? Optional.empty() : Optional.of(v.toCharArray());
    }
}

package org.example.jena.provenance.cert;

import java.nio.file.Path;

/**
 * The process-wide signing key.
 * <p>
 * Location, in order: environment {@code PROVENANCE_SIGNING_KEY}, system property
 * {@code jip.signingKey}, {@code $FUSEKI_BASE/provenance/signing-key.pem}, and
 * {@code ./provenance/signing-key.pem}. The key is generated once if the file is missing.
 */
public final class ProvenanceKeys {
    private ProvenanceKeys() {}

    public static final String ENV_KEY_FILE = "PROVENANCE_SIGNING_KEY";
    public static final String PROP_KEY_FILE = "jip.signingKey";

    private static volatile SigningKey key;

    public static SigningKey get() {
        SigningKey k = key;
        if ( k == null ) {
            synchronized (ProvenanceKeys.class) {
                if ( key == null )
                    key = SigningKey.loadOrGenerate(keyFile());
                k = key;
            }
        }
        return k;
    }

    /** Use this key (tests, embedded use). */
    public static synchronized void set(SigningKey signingKey) {
        key = signingKey;
    }

    public static Path keyFile() {
        String f = System.getenv(ENV_KEY_FILE);
        if ( f == null || f.isBlank() )
            f = System.getProperty(PROP_KEY_FILE);
        if ( f != null && !f.isBlank() )
            return Path.of(f);
        String base = System.getenv("FUSEKI_BASE");
        if ( base == null || base.isBlank() )
            base = System.getProperty("FUSEKI_BASE", ".");
        return Path.of(base, "provenance", "signing-key.pem");
    }
}

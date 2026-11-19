package xyz.larsw.jip.attestation;

import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.ServiceLoader;

/**
 * The process-wide signer.
 * <p>
 * The {@link SignerProvider} is chosen by the environment variable {@value #ENV_SIGNER} or the
 * system property {@value #PROP_SIGNER}:
 * <ul>
 * <li>{@code pkcs11} (default): a P-256 or P-384 key on a PKCS#11 token; see {@link Pkcs11Signer}
 * for its settings.</li>
 * <li>{@code local}: an Ed25519 key in a PEM file, generated once if missing. The file is
 * {@code PROVENANCE_SIGNING_KEY}, {@code jip.signingKey}, {@code $FUSEKI_BASE/provenance/signing-key.pem}
 * or {@code ./provenance/signing-key.pem}.</li>
 * <li>any other name registered as a {@link SignerProvider} service.</li>
 * </ul>
 */
public final class ProvenanceKeys {
    private ProvenanceKeys() {}

    public static final String ENV_SIGNER = "PROVENANCE_SIGNER";
    public static final String PROP_SIGNER = "jip.signer";
    public static final String DEFAULT_SIGNER = "pkcs11";

    public static final String ENV_KEY_FILE = "PROVENANCE_SIGNING_KEY";
    public static final String PROP_KEY_FILE = "jip.signingKey";

    private static volatile ProvenanceSigner signer;

    public static ProvenanceSigner get() {
        ProvenanceSigner s = signer;
        if ( s == null ) {
            synchronized (ProvenanceKeys.class) {
                if ( signer == null )
                    signer = open(SignerSettings.system());
                s = signer;
            }
        }
        return s;
    }

    /** Use this signer (tests, embedded use); null to choose again from the settings. */
    public static synchronized void set(ProvenanceSigner provenanceSigner) {
        signer = provenanceSigner;
    }

    /** Open the signer the settings name. */
    public static ProvenanceSigner open(SignerSettings settings) {
        String name = settings.get(ENV_SIGNER, PROP_SIGNER).orElse(DEFAULT_SIGNER);
        List<String> available = new ArrayList<>();
        for ( SignerProvider p : ServiceLoader.load(SignerProvider.class, ProvenanceKeys.class.getClassLoader()) ) {
            if ( p.name().equals(name) )
                return p.open(settings);
            available.add(p.name());
        }
        throw new IllegalStateException("Unknown signer '" + name + "' (" + ENV_SIGNER + "); available: " + available);
    }

    /** The key file of the {@code local} signer. */
    public static Path keyFile() {
        return keyFile(SignerSettings.system());
    }

    static Path keyFile(SignerSettings settings) {
        return settings.get(ENV_KEY_FILE, PROP_KEY_FILE).map(Path::of).orElseGet(() -> {
            String base = System.getenv("FUSEKI_BASE");
            if ( base == null || base.isBlank() )
                base = System.getProperty("FUSEKI_BASE", ".");
            return Path.of(base, "provenance", "signing-key.pem");
        });
    }
}

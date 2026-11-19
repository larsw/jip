package xyz.larsw.jip.cert;

/**
 * A way to sign certificates, found with {@link java.util.ServiceLoader} and selected by name
 * ({@code PROVENANCE_SIGNER} / {@code jip.signer}; see {@link ProvenanceKeys}). Built in:
 * {@code pkcs11} (the default: a key on a PKCS#11 token, for example an HSM or SoftHSM behind
 * {@code p11-kit server}) and {@code local} (an Ed25519 key in a PEM file).
 * <p>
 * To add another mechanism, implement this interface and list the class in
 * {@code META-INF/services/xyz.larsw.jip.cert.SignerProvider}.
 */
public interface SignerProvider {

    /** The name used to select this provider. */
    String name();

    /**
     * Open the signer.
     *
     * @throws IllegalStateException if it is not configured or the key cannot be used
     */
    ProvenanceSigner open(SignerSettings settings);
}

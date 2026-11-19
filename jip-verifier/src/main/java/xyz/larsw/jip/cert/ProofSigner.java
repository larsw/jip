package xyz.larsw.jip.cert;

/**
 * What {@link DataIntegrityProof#sign} needs from a key: its type (which selects the
 * cryptosuite), the verification method to name in the proof, and a signature over the proof's
 * hash data.
 */
public interface ProofSigner {
    /** {@code did:key:...#...}; see {@link DidKey#verificationMethod(java.security.PublicKey)}. */
    String verificationMethod();

    /**
     * Signature of {@code data} with {@link KeyType#signatureAlgorithm()}: Ed25519, or ECDSA
     * with SHA-256 (P-256) / SHA-384 (P-384) in IEEE P1363 format ({@code r || s}).
     */
    byte[] sign(byte[] data);

    /** The key type; Ed25519 unless overridden. */
    default KeyType keyType() {
        return KeyType.ED25519;
    }
}

package xyz.larsw.jip.cert;

/**
 * What {@link DataIntegrityProof#sign} needs from a key: the verification method to name in
 * the proof and an Ed25519 signature over the proof's hash data.
 */
public interface ProofSigner {
    /** {@code did:key:z6Mk...#z6Mk...}; see {@link DidKey#verificationMethod(byte[])}. */
    String verificationMethod();

    /** Ed25519 signature of {@code data}. */
    byte[] sign(byte[] data);
}

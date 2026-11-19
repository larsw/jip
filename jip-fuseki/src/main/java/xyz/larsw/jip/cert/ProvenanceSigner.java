package xyz.larsw.jip.cert;

import java.security.PublicKey;

/**
 * The server's signing key, wherever it lives: a {@link ProofSigner} that also publishes its
 * public key. Implementations come from {@link SignerProvider}s.
 */
public interface ProvenanceSigner extends ProofSigner {

    /** The provider name: {@code "pkcs11"}, {@code "local"}, ... */
    String kind();

    /** Where the key is, for logs. */
    String description();

    PublicKey publicKey();

    @Override
    default KeyType keyType() {
        return DidKey.keyType(publicKey());
    }

    @Override
    default String verificationMethod() {
        return DidKey.verificationMethod(publicKey());
    }

    /** {@code did:key:...} */
    default String didKey() {
        return DidKey.didKey(publicKey());
    }

    /** {@code z6Mk...}, {@code zDn...} or {@code z82...} */
    default String publicKeyMultibase() {
        return DidKey.publicKeyMultibase(publicKey());
    }

    /** Public key as a JWK (RFC 7517; OKP per RFC 8037, EC per RFC 7518). */
    default String jwk() {
        return KeyFormats.jwk(publicKey());
    }

    /** Public key as a PEM {@code PUBLIC KEY} block. */
    default String publicPem() {
        return KeyFormats.pem(publicKey());
    }
}

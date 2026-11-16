package org.example.jena.provenance.cert;

import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.HexFormat;

/**
 * Ed25519 public keys as {@code did:key} identifiers (https://w3c-ccg.github.io/did-key-spec/),
 * and Ed25519 signature verification with such a key.
 * <ul>
 * <li>{@code publicKeyMultibase}: {@code z} + base58btc(multicodec ed25519-pub + raw key), the
 * {@code z6Mk...} form.</li>
 * <li>{@code did:key:z6Mk...}: the DID.</li>
 * <li>{@code did:key:z6Mk...#z6Mk...}: the verification method named in proofs.</li>
 * </ul>
 */
public final class DidKey {
    private DidKey() {}

    private static final String PREFIX = "did:key:";
    /** multicodec ed25519-pub (0xed) as unsigned varint. */
    private static final byte[] MULTICODEC_ED25519_PUB = { (byte)0xed, 0x01 };
    /** DER prefix of an X.509 SubjectPublicKeyInfo for Ed25519. */
    private static final byte[] X509_PREFIX = HexFormat.of().parseHex("302a300506032b6570032100");
    private static final int KEY_LENGTH = 32;

    /** {@code z6Mk...} for a raw 32-byte Ed25519 public key. */
    public static String publicKeyMultibase(byte[] rawPublicKey) {
        return Base58.encodeMultibase(concat(MULTICODEC_ED25519_PUB, checkLength(rawPublicKey)));
    }

    /** {@code did:key:z6Mk...} for a raw 32-byte Ed25519 public key. */
    public static String didKey(byte[] rawPublicKey) {
        return PREFIX + publicKeyMultibase(rawPublicKey);
    }

    /** {@code did:key:z6Mk...#z6Mk...} for a raw 32-byte Ed25519 public key. */
    public static String verificationMethod(byte[] rawPublicKey) {
        String mb = publicKeyMultibase(rawPublicKey);
        return PREFIX + mb + "#" + mb;
    }

    /**
     * Raw Ed25519 public key from a {@code did:key} or a {@code did:key} verification method.
     *
     * @throws IllegalArgumentException if it is not an Ed25519 {@code did:key}, or the fragment
     *         names a different key
     */
    public static byte[] publicKey(String didKeyOrVerificationMethod) {
        String s = didKeyOrVerificationMethod;
        if ( !s.startsWith(PREFIX) )
            throw new IllegalArgumentException("Not a did:key: " + s);
        String fingerprint = s.substring(PREFIX.length());
        int hash = fingerprint.indexOf('#');
        if ( hash >= 0 ) {
            String fragment = fingerprint.substring(hash + 1);
            fingerprint = fingerprint.substring(0, hash);
            if ( !fragment.equals(fingerprint) )
                throw new IllegalArgumentException("did:key fragment does not match the key: " + s);
        }
        byte[] bytes = Base58.decodeMultibase(fingerprint);
        if ( bytes.length != KEY_LENGTH + 2 || bytes[0] != MULTICODEC_ED25519_PUB[0] || bytes[1] != MULTICODEC_ED25519_PUB[1] )
            throw new IllegalArgumentException("did:key is not an Ed25519 key: " + s);
        return Arrays.copyOfRange(bytes, 2, KEY_LENGTH + 2);
    }

    /** Verify an Ed25519 signature with a raw 32-byte public key. */
    public static boolean verify(byte[] rawPublicKey, byte[] data, byte[] signature) {
        try {
            PublicKey pub = KeyFactory.getInstance("Ed25519").generatePublic(new X509EncodedKeySpec(toSpki(rawPublicKey)));
            Signature sig = Signature.getInstance("Ed25519");
            sig.initVerify(pub);
            sig.update(data);
            return sig.verify(signature);
        } catch (GeneralSecurityException | IllegalArgumentException ex) {
            return false;
        }
    }

    /** DER X.509 SubjectPublicKeyInfo for a raw 32-byte Ed25519 public key. */
    public static byte[] toSpki(byte[] rawPublicKey) {
        return concat(X509_PREFIX, checkLength(rawPublicKey));
    }

    /** Raw 32-byte Ed25519 public key from a DER X.509 SubjectPublicKeyInfo. */
    public static byte[] fromSpki(byte[] spki) {
        if ( spki.length != X509_PREFIX.length + KEY_LENGTH || !Arrays.equals(Arrays.copyOf(spki, X509_PREFIX.length), X509_PREFIX) )
            throw new IllegalArgumentException("Not an Ed25519 SubjectPublicKeyInfo");
        return Arrays.copyOfRange(spki, X509_PREFIX.length, spki.length);
    }

    private static byte[] checkLength(byte[] rawPublicKey) {
        if ( rawPublicKey.length != KEY_LENGTH )
            throw new IllegalArgumentException("Ed25519 public key must be 32 bytes");
        return rawPublicKey;
    }

    private static byte[] concat(byte[] a, byte[] b) {
        byte[] r = Arrays.copyOf(a, a.length + b.length);
        System.arraycopy(b, 0, r, a.length, b.length);
        return r;
    }
}

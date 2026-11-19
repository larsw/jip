package xyz.larsw.jip.cert;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;

import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.edec.EdECObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x9.ECNamedCurveTable;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;

/**
 * Public keys as {@code did:key} identifiers (https://w3c-ccg.github.io/did-key-spec/), and
 * signature verification with such a key. Supported key types are those of {@link KeyType}:
 * <ul>
 * <li>Ed25519: {@code z} + base58btc(multicodec ed25519-pub {@code 0xed} + raw key), the
 * {@code z6Mk...} form.</li>
 * <li>P-256 / P-384: {@code z} + base58btc(multicodec p256-pub {@code 0x1200} /
 * p384-pub {@code 0x1201} + compressed point), the {@code zDn...} / {@code z82...} forms.</li>
 * </ul>
 * {@code did:key:<multibase>} is the DID, {@code did:key:<multibase>#<multibase>} the
 * verification method named in proofs.
 */
public final class DidKey {
    private DidKey() {}

    /** A public key named by a did:key. */
    public record Key(KeyType type, PublicKey publicKey) {}

    /**
     * The public key of a {@code did:key} or a {@code did:key} verification method, of any
     * supported type.
     *
     * @throws IllegalArgumentException if it is not a did:key, the key type is not supported,
     *         the key is malformed, or the fragment names a different key
     */
    public static Key resolve(String didKeyOrVerificationMethod) {
        byte[] bytes = Base58.decodeMultibase(fingerprint(didKeyOrVerificationMethod));
        KeyType type = KeyType.fromMulticodec(bytes)
                .orElseThrow(() -> new IllegalArgumentException("Unsupported did:key type: " + didKeyOrVerificationMethod));
        if ( bytes.length != 2 + type.encodedLength() )
            throw new IllegalArgumentException("Malformed " + type.curveName() + " did:key: " + didKeyOrVerificationMethod);
        return new Key(type, toPublicKey(type, Arrays.copyOfRange(bytes, 2, bytes.length)));
    }

    /** The key type of a JCA public key. */
    public static KeyType keyType(PublicKey key) {
        return encode(key).type();
    }

    /** {@code z6Mk...}, {@code zDn...} or {@code z82...} for a JCA public key. */
    public static String publicKeyMultibase(PublicKey key) {
        Encoded e = encode(key);
        return Base58.encodeMultibase(concat(e.type().multicodec(), e.bytes()));
    }

    /** {@code did:key:...} for a JCA public key. */
    public static String didKey(PublicKey key) {
        return PREFIX + publicKeyMultibase(key);
    }

    /** {@code did:key:...#...} for a JCA public key. */
    public static String verificationMethod(PublicKey key) {
        String mb = publicKeyMultibase(key);
        return PREFIX + mb + "#" + mb;
    }

    /** Verify a signature (P1363 {@code r || s} for ECDSA) over {@code data} with the key's algorithm. */
    public static boolean verify(Key key, byte[] data, byte[] signature) {
        try {
            Signature sig = Signature.getInstance(key.type().signatureAlgorithm());
            sig.initVerify(key.publicKey());
            sig.update(data);
            return sig.verify(signature);
        } catch (GeneralSecurityException | IllegalArgumentException ex) {
            return false;
        }
    }

    /** Key type and did:key bytes (raw key or compressed point). */
    private record Encoded(KeyType type, byte[] bytes) {}

    private static Encoded encode(PublicKey key) {
        SubjectPublicKeyInfo info;
        try {
            info = SubjectPublicKeyInfo.getInstance(key.getEncoded());
        } catch (RuntimeException ex) {
            throw new IllegalArgumentException("Unreadable public key: " + ex.getMessage(), ex);
        }
        ASN1ObjectIdentifier alg = info.getAlgorithm().getAlgorithm();
        if ( EdECObjectIdentifiers.id_Ed25519.equals(alg) )
            return new Encoded(KeyType.ED25519, checkLength(info.getPublicKeyData().getOctets()));
        if ( X9ObjectIdentifiers.id_ecPublicKey.equals(alg) && info.getAlgorithm().getParameters() instanceof ASN1ObjectIdentifier curve ) {
            for ( KeyType t : KeyType.values() ) {
                if ( t.isEcdsa() && curve.equals(ECNamedCurveTable.getOID(t.jcaCurve())) ) {
                    X9ECParameters params = ECNamedCurveTable.getByOID(curve);
                    return new Encoded(t, params.getCurve().decodePoint(info.getPublicKeyData().getOctets()).getEncoded(true));
                }
            }
        }
        throw new IllegalArgumentException("Unsupported public key: " + key.getAlgorithm() + " " + info.getAlgorithm().getAlgorithm()
                                           + " (supported: Ed25519, P-256, P-384)");
    }

    private static PublicKey toPublicKey(KeyType type, byte[] bytes) {
        try {
            byte[] spki;
            if ( type == KeyType.ED25519 ) {
                spki = toSpki(bytes);
            } else {
                X9ECParameters params = ECNamedCurveTable.getByName(type.jcaCurve());
                byte[] uncompressed = params.getCurve().decodePoint(bytes).getEncoded(false);   // checks the point is on the curve
                spki = new SubjectPublicKeyInfo(new AlgorithmIdentifier(X9ObjectIdentifiers.id_ecPublicKey, ECNamedCurveTable.getOID(type.jcaCurve())),
                                                uncompressed).getEncoded(ASN1Encoding.DER);
            }
            return KeyFactory.getInstance(type == KeyType.ED25519 ? "Ed25519" : "EC").generatePublic(new X509EncodedKeySpec(spki));
        } catch (IOException | GeneralSecurityException | RuntimeException ex) {
            throw new IllegalArgumentException("Bad " + type.curveName() + " public key: " + ex.getMessage(), ex);
        }
    }

    private static String fingerprint(String s) {
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
        return fingerprint;
    }

    private static final String PREFIX = "did:key:";
    /** multicodec ed25519-pub (0xed) as unsigned varint. */
    private static final byte[] MULTICODEC_ED25519_PUB = { (byte)0xed, 0x01 };
    /** id-Ed25519 without parameters (RFC 8410). */
    private static final AlgorithmIdentifier ED25519 = new AlgorithmIdentifier(EdECObjectIdentifiers.id_Ed25519);
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
        byte[] bytes = Base58.decodeMultibase(fingerprint(s));
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

    /** DER X.509 SubjectPublicKeyInfo for a raw 32-byte Ed25519 public key (RFC 8410). */
    public static byte[] toSpki(byte[] rawPublicKey) {
        try {
            return new SubjectPublicKeyInfo(ED25519, checkLength(rawPublicKey)).getEncoded(ASN1Encoding.DER);
        } catch (IOException ex) {
            throw new UncheckedIOException(ex);
        }
    }

    /** Raw 32-byte Ed25519 public key from a DER X.509 SubjectPublicKeyInfo. */
    public static byte[] fromSpki(byte[] spki) {
        SubjectPublicKeyInfo info;
        try {
            info = SubjectPublicKeyInfo.getInstance(spki);
        } catch (RuntimeException ex) {
            throw new IllegalArgumentException("Not an Ed25519 SubjectPublicKeyInfo", ex);
        }
        if ( info == null || !ED25519.equals(info.getAlgorithm()) || info.getPublicKeyData().getPadBits() != 0 )
            throw new IllegalArgumentException("Not an Ed25519 SubjectPublicKeyInfo");
        return checkLength(info.getPublicKeyData().getOctets());
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

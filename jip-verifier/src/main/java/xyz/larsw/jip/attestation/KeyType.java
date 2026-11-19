package xyz.larsw.jip.attestation;

import java.util.Arrays;
import java.util.Optional;

/**
 * The key types an attestation can be signed with, and what each implies: the W3C Data Integrity
 * cryptosuite, the hash used for the proof's hash data, the JCA signature algorithm and the
 * {@code did:key} multicodec prefix.
 * <ul>
 * <li>{@link #ED25519}: {@code eddsa-rdfc-2022} (W3C vc-di-eddsa), SHA-256.</li>
 * <li>{@link #P256}, {@link #P384}: {@code ecdsa-rdfc-2019} (W3C vc-di-ecdsa), SHA-256 or
 * SHA-384; signatures are IEEE P1363 ({@code r || s}).</li>
 * </ul>
 */
public enum KeyType {
    /** Ed25519; did:key {@code z6Mk...}, raw 32-byte key. */
    ED25519("Ed25519", "eddsa-rdfc-2022", "SHA-256", "Ed25519", null, 32, (byte)0xed, (byte)0x01),
    /** NIST P-256 (secp256r1); did:key {@code zDn...}, compressed point (33 bytes). */
    P256("P-256", "ecdsa-rdfc-2019", "SHA-256", "SHA256withECDSAinP1363Format", "secp256r1", 33, (byte)0x80, (byte)0x24),
    /** NIST P-384 (secp384r1); did:key {@code z82...}, compressed point (49 bytes). */
    P384("P-384", "ecdsa-rdfc-2019", "SHA-384", "SHA384withECDSAinP1363Format", "secp384r1", 49, (byte)0x81, (byte)0x24);

    /** Cryptosuite of Ed25519 keys. */
    public static final String EDDSA_RDFC_2022 = "eddsa-rdfc-2022";
    /** Cryptosuite of P-256 and P-384 keys. */
    public static final String ECDSA_RDFC_2019 = "ecdsa-rdfc-2019";

    private final String curveName;
    private final String cryptosuite;
    private final String digest;
    private final String signatureAlgorithm;
    private final String jcaCurve;
    private final int encodedLength;
    private final byte[] multicodec;

    KeyType(String curveName, String cryptosuite, String digest, String signatureAlgorithm, String jcaCurve, int encodedLength,
            byte... multicodec) {
        this.curveName = curveName;
        this.cryptosuite = cryptosuite;
        this.digest = digest;
        this.signatureAlgorithm = signatureAlgorithm;
        this.jcaCurve = jcaCurve;
        this.encodedLength = encodedLength;
        this.multicodec = multicodec;
    }

    /** "Ed25519", "P-256" or "P-384". */
    public String curveName() {
        return curveName;
    }

    /** The Data Integrity cryptosuite for this key type. */
    public String cryptosuite() {
        return cryptosuite;
    }

    /** JCA name of the hash used for the proof's hash data ("SHA-256", "SHA-384"). */
    public String digest() {
        return digest;
    }

    /** JCA signature algorithm over the hash data (P1363 encoding for ECDSA). */
    public String signatureAlgorithm() {
        return signatureAlgorithm;
    }

    /** JCA curve name for EC keys ("secp256r1", "secp384r1"); null for Ed25519. */
    public String jcaCurve() {
        return jcaCurve;
    }

    /** The JWS algorithm name for JWKs (RFC 7518, RFC 8037): "EdDSA", "ES256" or "ES384". */
    public String jwsAlgorithm() {
        return switch (this) {
            case ED25519 -> "EdDSA";
            case P256 -> "ES256";
            case P384 -> "ES384";
        };
    }

    public boolean isEcdsa() {
        return jcaCurve != null;
    }

    /** Length of the key bytes in a did:key: raw key (Ed25519) or compressed point (EC). */
    int encodedLength() {
        return encodedLength;
    }

    /** The multicodec prefix (unsigned varint) of the key in a did:key. */
    byte[] multicodec() {
        return multicodec.clone();
    }

    /** The key type whose multicodec prefix starts {@code bytes}. */
    static Optional<KeyType> fromMulticodec(byte[] bytes) {
        for ( KeyType t : values() ) {
            if ( bytes.length >= 2 && Arrays.equals(Arrays.copyOf(bytes, 2), t.multicodec) )
                return Optional.of(t);
        }
        return Optional.empty();
    }

    /** "P-256", "p256", "secp256r1", "P-384", ... (case-insensitive). */
    public static KeyType parseCurve(String name) {
        String n = name.strip().toLowerCase(java.util.Locale.ROOT).replace("-", "");
        return switch (n) {
            case "p256", "secp256r1", "prime256v1" -> P256;
            case "p384", "secp384r1" -> P384;
            case "ed25519" -> ED25519;
            default -> throw new IllegalArgumentException("Unknown key type: " + name + " (expected P-256, P-384 or Ed25519)");
        };
    }
}

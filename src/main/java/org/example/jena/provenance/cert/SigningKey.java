package org.example.jena.provenance.cert;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.interfaces.EdECPrivateKey;
import java.security.spec.NamedParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;
import java.util.HexFormat;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * An Ed25519 signing key, published as a {@code did:key}.
 * <p>
 * Stored as PEM with a {@code PRIVATE KEY} (PKCS#8) block and, when written by this class, a
 * {@code PUBLIC KEY} block. The JDK has no API to derive an Ed25519 public key from a private
 * key, so the key pair is regenerated from the 32-byte seed through the JDK's own generator
 * (RFC 8032 key generation is deterministic in the seed).
 */
public final class SigningKey {
    private static final Logger LOG = LoggerFactory.getLogger(SigningKey.class);

    /** multicodec ed25519-pub (0xed) as unsigned varint. */
    private static final byte[] MULTICODEC_ED25519_PUB = { (byte)0xed, 0x01 };
    /** multicodec ed25519-priv (0x1300) as unsigned varint. */
    private static final byte[] MULTICODEC_ED25519_PRIV = { (byte)0x80, 0x26 };
    /** DER prefix of an X.509 SubjectPublicKeyInfo for Ed25519. */
    private static final byte[] X509_PREFIX = HexFormat.of().parseHex("302a300506032b6570032100");
    /** DER prefix of a PKCS#8 PrivateKeyInfo for Ed25519. */
    private static final byte[] PKCS8_PREFIX = HexFormat.of().parseHex("302e020100300506032b657004220420");

    private final PrivateKey privateKey;
    private final byte[] rawPublicKey;

    private SigningKey(PrivateKey privateKey, byte[] rawPublicKey) {
        this.privateKey = privateKey;
        this.rawPublicKey = rawPublicKey;
    }

    // ---- Construction

    /** Generate a new random key. */
    public static SigningKey generate() {
        byte[] seed = new byte[32];
        new SecureRandom().nextBytes(seed);
        return fromSeed(seed);
    }

    /** Key from a 32-byte Ed25519 seed (the RFC 8032 private key). */
    public static SigningKey fromSeed(byte[] seed) {
        if ( seed.length != 32 )
            throw new IllegalArgumentException("Ed25519 seed must be 32 bytes");
        try {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("Ed25519");
            kpg.initialize(NamedParameterSpec.ED25519, new FixedSeedRandom(seed));
            KeyPair kp = kpg.generateKeyPair();
            return new SigningKey(kp.getPrivate(), rawPublic(kp.getPublic()));
        } catch (GeneralSecurityException ex) {
            throw new IllegalStateException("Ed25519 not available", ex);
        }
    }

    /** Key from a multibase {@code privateKeyMultibase} (multicodec ed25519-priv). */
    public static SigningKey fromPrivateKeyMultibase(String multibase) {
        byte[] bytes = Base58.decodeMultibase(multibase);
        if ( bytes.length != 34 || bytes[0] != MULTICODEC_ED25519_PRIV[0] || bytes[1] != MULTICODEC_ED25519_PRIV[1] )
            throw new IllegalArgumentException("Not an Ed25519 privateKeyMultibase");
        return fromSeed(Arrays.copyOfRange(bytes, 2, 34));
    }

    /** Key from PEM text (PKCS#8 PRIVATE KEY; an optional PUBLIC KEY block is checked). */
    public static SigningKey fromPem(String pem) {
        byte[] pkcs8 = pemBlock(pem, "PRIVATE KEY");
        if ( pkcs8 == null )
            throw new IllegalArgumentException("No PRIVATE KEY block in PEM");
        try {
            PrivateKey pk = KeyFactory.getInstance("Ed25519").generatePrivate(new PKCS8EncodedKeySpec(pkcs8));
            if ( !(pk instanceof EdECPrivateKey edPk) || edPk.getBytes().isEmpty() )
                throw new IllegalArgumentException("Not an Ed25519 private key");
            SigningKey key = fromSeed(edPk.getBytes().get());
            byte[] spki = pemBlock(pem, "PUBLIC KEY");
            if ( spki != null && !Arrays.equals(rawPublic(spki), key.rawPublicKey) )
                throw new IllegalArgumentException("PUBLIC KEY block does not match the PRIVATE KEY");
            return key;
        } catch (GeneralSecurityException ex) {
            throw new IllegalArgumentException("Bad Ed25519 PKCS#8 key: " + ex.getMessage(), ex);
        }
    }

    /**
     * Load the key from {@code pemFile}, or generate one and write it there (mode 600) if the
     * file does not exist.
     */
    public static SigningKey loadOrGenerate(Path pemFile) {
        try {
            if ( Files.exists(pemFile) )
                return fromPem(Files.readString(pemFile, StandardCharsets.US_ASCII));
            SigningKey key = generate();
            Files.createDirectories(pemFile.toAbsolutePath().getParent());
            Path tmp = pemFile.resolveSibling(pemFile.getFileName() + ".tmp");
            Files.writeString(tmp, key.toPem(), StandardCharsets.US_ASCII);
            try {
                Files.setPosixFilePermissions(tmp, PosixFilePermissions.fromString("rw-------"));
            } catch (UnsupportedOperationException ignored) {}
            Files.move(tmp, pemFile);
            LOG.info("Generated new provenance signing key {} at {}", key.didKey(), pemFile);
            return key;
        } catch (IOException ex) {
            throw new UncheckedIOException("Signing key " + pemFile, ex);
        }
    }

    // ---- Use

    public byte[] sign(byte[] data) {
        try {
            Signature sig = Signature.getInstance("Ed25519");
            sig.initSign(privateKey);
            sig.update(data);
            return sig.sign();
        } catch (GeneralSecurityException ex) {
            throw new IllegalStateException("Ed25519 signing failed", ex);
        }
    }

    /** Verify an Ed25519 signature with a raw 32-byte public key. */
    public static boolean verify(byte[] rawPublicKey, byte[] data, byte[] signature) {
        try {
            byte[] spki = concat(X509_PREFIX, rawPublicKey);
            PublicKey pub = KeyFactory.getInstance("Ed25519").generatePublic(new X509EncodedKeySpec(spki));
            Signature sig = Signature.getInstance("Ed25519");
            sig.initVerify(pub);
            sig.update(data);
            return sig.verify(signature);
        } catch (GeneralSecurityException ex) {
            return false;
        }
    }

    // ---- Identifiers

    public byte[] rawPublicKey() {
        return rawPublicKey.clone();
    }

    /** {@code z6Mk...}: multibase(multicodec ed25519-pub + raw key). */
    public String publicKeyMultibase() {
        return Base58.encodeMultibase(concat(MULTICODEC_ED25519_PUB, rawPublicKey));
    }

    /** {@code did:key:z6Mk...} */
    public String didKey() {
        return "did:key:" + publicKeyMultibase();
    }

    /** {@code did:key:z6Mk...#z6Mk...} : the verification method used in proofs. */
    public String verificationMethod() {
        return didKey() + "#" + publicKeyMultibase();
    }

    /** Raw Ed25519 public key from a {@code did:key} or a {@code did:key} verification method. */
    public static byte[] publicKeyFromDidKey(String didKeyOrVerificationMethod) {
        String s = didKeyOrVerificationMethod;
        if ( !s.startsWith("did:key:") )
            throw new IllegalArgumentException("Not a did:key: " + s);
        String fingerprint = s.substring("did:key:".length());
        int hash = fingerprint.indexOf('#');
        if ( hash >= 0 ) {
            String fragment = fingerprint.substring(hash + 1);
            fingerprint = fingerprint.substring(0, hash);
            if ( !fragment.equals(fingerprint) )
                throw new IllegalArgumentException("did:key fragment does not match the key: " + s);
        }
        byte[] bytes = Base58.decodeMultibase(fingerprint);
        if ( bytes.length != 34 || bytes[0] != MULTICODEC_ED25519_PUB[0] || bytes[1] != MULTICODEC_ED25519_PUB[1] )
            throw new IllegalArgumentException("did:key is not an Ed25519 key: " + s);
        return Arrays.copyOfRange(bytes, 2, 34);
    }

    /** Public key as a JWK (RFC 8037). */
    public String jwk() {
        String x = Base64.getUrlEncoder().withoutPadding().encodeToString(rawPublicKey);
        return "{\"kty\":\"OKP\",\"crv\":\"Ed25519\",\"x\":\"" + x + "\"}";
    }

    public String publicPem() {
        return pem("PUBLIC KEY", concat(X509_PREFIX, rawPublicKey));
    }

    /** PRIVATE KEY (PKCS#8) and PUBLIC KEY blocks. */
    public String toPem() {
        byte[] seed = ((EdECPrivateKey)privateKey).getBytes().orElseThrow();
        return pem("PRIVATE KEY", concat(PKCS8_PREFIX, seed)) + publicPem();
    }

    // ---- Helpers

    private static byte[] rawPublic(PublicKey pub) {
        return rawPublic(pub.getEncoded());
    }

    private static byte[] rawPublic(byte[] spki) {
        if ( spki.length != 44 || !Arrays.equals(Arrays.copyOf(spki, 12), X509_PREFIX) )
            throw new IllegalArgumentException("Not an Ed25519 SubjectPublicKeyInfo");
        return Arrays.copyOfRange(spki, 12, 44);
    }

    private static String pem(String type, byte[] der) {
        String b64 = Base64.getMimeEncoder(64, "\n".getBytes(StandardCharsets.US_ASCII)).encodeToString(der);
        return "-----BEGIN " + type + "-----\n" + b64 + "\n-----END " + type + "-----\n";
    }

    private static byte[] pemBlock(String pem, String type) {
        Pattern p = Pattern.compile("-----BEGIN " + type + "-----(.*?)-----END " + type + "-----", Pattern.DOTALL);
        Matcher m = p.matcher(pem);
        if ( !m.find() )
            return null;
        return Base64.getMimeDecoder().decode(m.group(1).replaceAll("\\s", ""));
    }

    private static byte[] concat(byte[] a, byte[] b) {
        byte[] r = Arrays.copyOf(a, a.length + b.length);
        System.arraycopy(b, 0, r, a.length, b.length);
        return r;
    }

    /** Supplies the given seed to the JDK Ed25519 key pair generator. */
    private static final class FixedSeedRandom extends SecureRandom {
        private static final long serialVersionUID = 1L;
        private final byte[] seed;

        FixedSeedRandom(byte[] seed) {
            this.seed = seed.clone();
        }

        @Override
        public void nextBytes(byte[] bytes) {
            if ( bytes.length != seed.length )
                throw new IllegalStateException("Unexpected request for " + bytes.length + " random bytes");
            System.arraycopy(seed, 0, bytes, 0, seed.length);
        }
    }
}

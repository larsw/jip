package xyz.larsw.jip.attestation;

import java.io.IOException;
import java.io.StringReader;
import java.io.StringWriter;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;

import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.edec.EdECObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;
import org.bouncycastle.util.io.pem.PemWriter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * An Ed25519 signing key, published as a {@code did:key} (see {@link DidKey}).
 * <p>
 * Stored as PEM with a {@code PRIVATE KEY} (PKCS#8) block and, when written by this class, a
 * {@code PUBLIC KEY} block. The key is held as its 32-byte RFC 8032 seed. BouncyCastle derives
 * the public key and handles the PKCS#8 and PEM encodings; signing uses the JDK's Ed25519.
 */
public final class SigningKey implements ProvenanceSigner {
    private static final Logger LOG = LoggerFactory.getLogger(SigningKey.class);

    /** multicodec ed25519-priv (0x1300) as unsigned varint. */
    private static final byte[] MULTICODEC_ED25519_PRIV = { (byte)0x80, 0x26 };
    private static final AlgorithmIdentifier ED25519 = new AlgorithmIdentifier(EdECObjectIdentifiers.id_Ed25519);
    private static final int SEED_LENGTH = Ed25519PrivateKeyParameters.KEY_SIZE;

    private final byte[] seed;
    private final PrivateKey privateKey;
    private final byte[] rawPublicKey;

    /** Where the key came from, for logs. */
    private volatile String source = "in memory";

    private SigningKey(byte[] seed) {
        this.seed = seed.clone();
        this.rawPublicKey = new Ed25519PrivateKeyParameters(seed, 0).generatePublicKey().getEncoded();
        try {
            this.privateKey = KeyFactory.getInstance("Ed25519").generatePrivate(new PKCS8EncodedKeySpec(pkcs8(seed)));
        } catch (GeneralSecurityException ex) {
            throw new IllegalStateException("Ed25519 not available", ex);
        }
    }

    // ---- Construction

    /** Generate a new random key. */
    public static SigningKey generate() {
        byte[] seed = new byte[SEED_LENGTH];
        new SecureRandom().nextBytes(seed);
        return new SigningKey(seed);
    }

    /** Key from a 32-byte Ed25519 seed (the RFC 8032 private key). */
    public static SigningKey fromSeed(byte[] seed) {
        if ( seed.length != SEED_LENGTH )
            throw new IllegalArgumentException("Ed25519 seed must be 32 bytes");
        return new SigningKey(seed);
    }

    /** Key from a multibase {@code privateKeyMultibase} (multicodec ed25519-priv). */
    public static SigningKey fromPrivateKeyMultibase(String multibase) {
        byte[] bytes = Base58.decodeMultibase(multibase);
        if ( bytes.length != SEED_LENGTH + 2 || bytes[0] != MULTICODEC_ED25519_PRIV[0] || bytes[1] != MULTICODEC_ED25519_PRIV[1] )
            throw new IllegalArgumentException("Not an Ed25519 privateKeyMultibase");
        return fromSeed(Arrays.copyOfRange(bytes, 2, SEED_LENGTH + 2));
    }

    /**
     * Key from PEM text: a PKCS#8 {@code PRIVATE KEY} block (version 1, or version 2 with the
     * public key), and optionally a {@code PUBLIC KEY} block. Any public key given must match.
     */
    public static SigningKey fromPem(String pem) {
        PemObject privateBlock = null;
        PemObject publicBlock = null;
        try ( PemReader reader = new PemReader(new StringReader(pem)) ) {
            for ( PemObject o = reader.readPemObject() ; o != null ; o = reader.readPemObject() ) {
                switch (o.getType()) {
                    case "PRIVATE KEY" -> privateBlock = privateBlock == null ? o : privateBlock;
                    case "PUBLIC KEY" -> publicBlock = publicBlock == null ? o : publicBlock;
                    default -> {}
                }
            }
        } catch (IOException ex) {
            throw new IllegalArgumentException("Bad PEM: " + ex.getMessage(), ex);
        }
        if ( privateBlock == null )
            throw new IllegalArgumentException("No PRIVATE KEY block in PEM");

        SigningKey key;
        byte[] embeddedPublic;
        try {
            PrivateKeyInfo info = PrivateKeyInfo.getInstance(privateBlock.getContent());
            if ( !EdECObjectIdentifiers.id_Ed25519.equals(info.getPrivateKeyAlgorithm().getAlgorithm()) )
                throw new IllegalArgumentException("Not an Ed25519 private key (algorithm "
                                                   + info.getPrivateKeyAlgorithm().getAlgorithm() + ")");
            key = fromSeed(ASN1OctetString.getInstance(info.parsePrivateKey()).getOctets());
            embeddedPublic = info.getPublicKeyData() == null ? null : info.getPublicKeyData().getOctets();
        } catch (IOException | RuntimeException ex) {
            if ( ex instanceof IllegalArgumentException iae && iae.getMessage() != null && iae.getMessage().startsWith("Not an Ed25519") )
                throw iae;
            throw new IllegalArgumentException("Bad Ed25519 PKCS#8 key: " + ex.getMessage(), ex);
        }
        if ( embeddedPublic != null && !Arrays.equals(embeddedPublic, key.rawPublicKey) )
            throw new IllegalArgumentException("Public key in the PKCS#8 block does not match the private key");
        if ( publicBlock != null && !Arrays.equals(DidKey.fromSpki(publicBlock.getContent()), key.rawPublicKey) )
            throw new IllegalArgumentException("PUBLIC KEY block does not match the PRIVATE KEY");
        return key;
    }

    /**
     * Load the key from {@code pemFile}, or generate one and write it there (mode 600) if the
     * file does not exist.
     */
    public static SigningKey loadOrGenerate(Path pemFile) {
        try {
            if ( Files.exists(pemFile) )
                return fromPem(Files.readString(pemFile, StandardCharsets.US_ASCII)).from("key file " + pemFile);
            SigningKey key = generate();
            Files.createDirectories(pemFile.toAbsolutePath().getParent());
            Path tmp = pemFile.resolveSibling(pemFile.getFileName() + ".tmp");
            Files.writeString(tmp, key.toPem(), StandardCharsets.US_ASCII);
            try {
                Files.setPosixFilePermissions(tmp, PosixFilePermissions.fromString("rw-------"));
            } catch (UnsupportedOperationException ignored) {}
            Files.move(tmp, pemFile);
            LOG.info("Generated new provenance signing key {} at {}", key.didKey(), pemFile);
            return key.from("key file " + pemFile);
        } catch (IOException ex) {
            throw new UncheckedIOException("Signing key " + pemFile, ex);
        }
    }

    // ---- Use

    @Override
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

    // ---- Identifiers

    public byte[] rawPublicKey() {
        return rawPublicKey.clone();
    }

    /** {@code z6Mk...}: multibase(multicodec ed25519-pub + raw key). */
    public String publicKeyMultibase() {
        return DidKey.publicKeyMultibase(rawPublicKey);
    }

    /** {@code did:key:z6Mk...} */
    public String didKey() {
        return DidKey.didKey(rawPublicKey);
    }

    /** {@code did:key:z6Mk...#z6Mk...} : the verification method used in proofs. */
    @Override
    public String verificationMethod() {
        return DidKey.verificationMethod(rawPublicKey);
    }

    private SigningKey from(String where) {
        this.source = where;
        return this;
    }

    @Override
    public String kind() {
        return "local";
    }

    @Override
    public String description() {
        return "Ed25519 " + source;
    }

    @Override
    public PublicKey publicKey() {
        try {
            return KeyFactory.getInstance("Ed25519").generatePublic(new X509EncodedKeySpec(DidKey.toSpki(rawPublicKey)));
        } catch (GeneralSecurityException ex) {
            throw new IllegalStateException(ex);
        }
    }

    @Override
    public KeyType keyType() {
        return KeyType.ED25519;
    }

    /** The built-in provider for {@code local}: an Ed25519 key in a PEM file, created if missing. */
    public static final class Factory implements SignerProvider {
        @Override
        public String name() {
            return "local";
        }

        @Override
        public ProvenanceSigner open(SignerSettings settings) {
            return loadOrGenerate(ProvenanceKeys.keyFile(settings));
        }
    }

    /** Public key as a JWK (RFC 8037). */
    @Override
    public String jwk() {
        String x = Base64.getUrlEncoder().withoutPadding().encodeToString(rawPublicKey);
        return "{\"kty\":\"OKP\",\"crv\":\"Ed25519\",\"x\":\"" + x + "\"}";
    }

    public String publicPem() {
        return pem(new PemObject("PUBLIC KEY", DidKey.toSpki(rawPublicKey)));
    }

    /** PRIVATE KEY (PKCS#8 version 1) and PUBLIC KEY blocks. */
    public String toPem() {
        return pem(new PemObject("PRIVATE KEY", pkcs8(seed))) + publicPem();
    }

    // ---- Helpers

    /** PKCS#8 PrivateKeyInfo (version 1) for an Ed25519 seed, DER (RFC 8410). */
    private static byte[] pkcs8(byte[] seed) {
        try {
            return new PrivateKeyInfo(ED25519, new DEROctetString(seed)).getEncoded(ASN1Encoding.DER);
        } catch (IOException ex) {
            throw new UncheckedIOException(ex);
        }
    }

    private static String pem(PemObject object) {
        StringWriter out = new StringWriter();
        try ( PemWriter w = new PemWriter(out) ) {
            w.writeObject(object);
        } catch (IOException ex) {
            throw new UncheckedIOException(ex);
        }
        return out.toString().replace("\r\n", "\n");
    }
}

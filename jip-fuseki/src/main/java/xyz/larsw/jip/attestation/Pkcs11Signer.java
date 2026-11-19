package xyz.larsw.jip.attestation;

import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;
import java.util.Date;
import java.util.Optional;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * A signing key on a PKCS#11 token, used through the JDK's SunPKCS11 provider. The private key
 * never leaves the token: signing is a {@code C_Sign} call into the PKCS#11 module.
 * <p>
 * The module can be a hardware HSM's library, SoftHSM, or {@code p11-kit-client.so}, which
 * forwards every call over a Unix socket to a {@code p11-kit server} in another process (the
 * Docker setup does this, so the Fuseki process holds no key material).
 * <p>
 * Keys are ECDSA P-256 or P-384 and sign with {@code ecdsa-rdfc-2019}; Java 21's SunPKCS11 has
 * no EdDSA support. The key is found by its label (key store alias); the JDK's PKCS#11 key store
 * only lists a private key that has a certificate with the same {@code CKA_ID}, so generated keys
 * get a self-signed certificate.
 */
public final class Pkcs11Signer implements ProvenanceSigner {
    private static final Logger LOG = LoggerFactory.getLogger(Pkcs11Signer.class);

    public static final String ENV_LIBRARY = "PROVENANCE_PKCS11_LIBRARY";
    public static final String PROP_LIBRARY = "jip.pkcs11.library";
    public static final String ENV_SLOT_INDEX = "PROVENANCE_PKCS11_SLOT_INDEX";
    public static final String PROP_SLOT_INDEX = "jip.pkcs11.slotIndex";
    public static final String ENV_CONFIG = "PROVENANCE_PKCS11_CONFIG";
    public static final String PROP_CONFIG = "jip.pkcs11.config";
    public static final String ENV_PIN = "PROVENANCE_PKCS11_PIN";
    public static final String PROP_PIN = "jip.pkcs11.pin";
    public static final String ENV_PIN_FILE = "PROVENANCE_PKCS11_PIN_FILE";
    public static final String PROP_PIN_FILE = "jip.pkcs11.pinFile";
    public static final String ENV_KEY = "PROVENANCE_PKCS11_KEY";
    public static final String PROP_KEY = "jip.pkcs11.key";
    public static final String ENV_GENERATE = "PROVENANCE_PKCS11_GENERATE";
    public static final String PROP_GENERATE = "jip.pkcs11.generate";

    public static final String DEFAULT_KEY_LABEL = "jip-signing";

    /**
     * What the provider needs, resolved from the settings: either a module {@code library} with
     * a {@code slotIndex}, or a SunPKCS11 {@code configFile}.
     */
    record Config(String library, int slotIndex, String configFile, String moduleDescription, char[] pin, String keyLabel,
                  Optional<KeyType> generate) {
        /** SunPKCS11 configuration, loading the module from {@code libraryPath}. */
        String providerConfig(String libraryPath) {
            return configFile != null ? configFile : "--name=jip\nlibrary=" + libraryPath + "\nslotListIndex=" + slotIndex + "\n";
        }
    }

    /** An open connection to the token and the key on it. */
    private record Session(Provider provider, PrivateKey privateKey, PublicKey publicKey) {}

    private final Config config;
    private final PublicKey publicKey;
    private final KeyType keyType;
    private volatile Session session;

    private Pkcs11Signer(Config config, Session session) {
        this.config = config;
        this.session = session;
        this.publicKey = session.publicKey();
        this.keyType = DidKey.keyType(publicKey);
    }

    /** Open the key described by the settings, generating it first if allowed. */
    public static Pkcs11Signer open(SignerSettings settings) {
        Config config = config(settings);
        Session s = connect(config, true, false);
        Pkcs11Signer signer = new Pkcs11Signer(config, s);
        if ( !signer.keyType.isEcdsa() )
            throw new IllegalStateException("PKCS#11 key '" + config.keyLabel() + "' is " + signer.keyType.curveName()
                                            + "; use a P-256 or P-384 key");
        return signer;
    }

    static Config config(SignerSettings settings) {
        Optional<String> configFile = settings.get(ENV_CONFIG, PROP_CONFIG);
        String library = null;
        int slotIndex = 0;
        String module;
        if ( configFile.isPresent() ) {
            module = "SunPKCS11 configuration " + configFile.get();
        } else {
            library = settings.get(ENV_LIBRARY, PROP_LIBRARY).orElseThrow(() -> new IllegalStateException(
                    "PKCS#11 signer: no module configured. Set " + ENV_LIBRARY + " to the PKCS#11 library (for example "
                    + "p11-kit-client.so, libsofthsm2.so or an HSM vendor's library), or " + ProvenanceKeys.ENV_SIGNER
                    + "=local to sign with a key file."));
            slotIndex = Integer.parseInt(settings.get(ENV_SLOT_INDEX, PROP_SLOT_INDEX).orElse("0"));
            module = library + " (slot index " + slotIndex + ")";
        }
        char[] pin = settings.secret(ENV_PIN, PROP_PIN, ENV_PIN_FILE, PROP_PIN_FILE).orElse(null);
        String label = settings.get(ENV_KEY, PROP_KEY).orElse(DEFAULT_KEY_LABEL);
        Optional<KeyType> generate = settings.get(ENV_GENERATE, PROP_GENERATE).map(KeyType::parseCurve);
        generate.filter(t -> !t.isEcdsa()).ifPresent(t -> {
            throw new IllegalStateException(ENV_GENERATE + " must be P-256 or P-384");
        });
        return new Config(library, slotIndex, configFile.orElse(null), module, pin, label, generate);
    }

    /**
     * Connect to the token. On a reconnect ({@code freshModule}), the JDK can't re-initialize a
     * module it has already loaded (it keeps one instance per library path, and a module such as
     * p11-kit-client.so stays broken after its server restarts), so the library is loaded from a
     * fresh copy: a new path is a new, independent instance. Not possible with a config file.
     */
    private static Session connect(Config config, boolean mayGenerate, boolean freshModule) {
        Provider base = Security.getProvider("SunPKCS11");
        if ( base == null )
            throw new IllegalStateException("The JDK has no SunPKCS11 provider (module jdk.crypto.cryptoki)");
        Provider provider;
        try {
            String libraryPath = config.library();
            if ( freshModule && libraryPath != null )
                libraryPath = freshCopy(libraryPath);
            provider = base.configure(config.providerConfig(libraryPath));
        } catch (RuntimeException ex) {
            throw new IllegalStateException("Cannot load PKCS#11 module " + config.moduleDescription() + ": " + rootMessage(ex), ex);
        }
        try {
            KeyStore ks = KeyStore.getInstance("PKCS11", provider);
            ks.load(null, config.pin() == null ? null : config.pin().clone());
            if ( !ks.isKeyEntry(config.keyLabel()) ) {
                if ( !mayGenerate || config.generate().isEmpty() )
                    throw new IllegalStateException("No key '" + config.keyLabel() + "' on the PKCS#11 token of " + config.moduleDescription()
                                                    + ". Create one, or set " + ENV_GENERATE + "=P-256 (or P-384) to have it created.");
                generate(provider, ks, config.keyLabel(), config.generate().get());
            }
            PrivateKey priv = (PrivateKey)ks.getKey(config.keyLabel(), null);
            Certificate cert = ks.getCertificate(config.keyLabel());
            if ( priv == null || cert == null )
                throw new IllegalStateException("PKCS#11 key '" + config.keyLabel() + "' has no private key or certificate");
            return new Session(provider, priv, cert.getPublicKey());
        } catch (GeneralSecurityException | java.io.IOException ex) {
            throw new IllegalStateException("PKCS#11 token of " + config.moduleDescription() + ": " + rootMessage(ex), ex);
        }
    }

    /** A copy of the module in a new temporary file, deleted when the JVM exits. */
    private static String freshCopy(String library) {
        try {
            java.nio.file.Path src = java.nio.file.Path.of(library).toRealPath();
            java.nio.file.Path copy = java.nio.file.Files.createTempFile("jip-pkcs11-", "-" + src.getFileName());
            java.nio.file.Files.copy(src, copy, java.nio.file.StandardCopyOption.REPLACE_EXISTING);
            copy.toFile().deleteOnExit();
            return copy.toString();
        } catch (java.io.IOException ex) {
            throw new IllegalStateException("Cannot copy PKCS#11 module " + library + ": " + ex.getMessage(), ex);
        }
    }

    /** Create a key pair on the token, with a self-signed certificate so the key store lists it. */
    private static void generate(Provider provider, KeyStore ks, String label, KeyType type) throws GeneralSecurityException {
        KeyPairGenerator g = KeyPairGenerator.getInstance("EC", provider);
        g.initialize(new ECGenParameterSpec(type.jcaCurve()));
        KeyPair kp = g.generateKeyPair();
        Instant now = Instant.now();
        X500Name name = new X500Name("CN=jena-intrinsic-provenance signing key");
        String sigAlg = type == KeyType.P384 ? "SHA384withECDSA" : "SHA256withECDSA";
        X509Certificate cert;
        try {
            cert = new JcaX509CertificateConverter().getCertificate(new JcaX509v3CertificateBuilder(
                    name, BigInteger.valueOf(now.toEpochMilli()), Date.from(now), Date.from(now.plus(Duration.ofDays(3650))), name, kp.getPublic())
                    .build(new JcaContentSignerBuilder(sigAlg).setProvider(provider).build(kp.getPrivate())));
        } catch (org.bouncycastle.operator.OperatorCreationException ex) {
            throw new GeneralSecurityException(ex.getMessage(), ex);
        }
        ks.setKeyEntry(label, kp.getPrivate(), null, new Certificate[] { cert });
        LOG.info("Generated {} signing key '{}' on the PKCS#11 token: {}", type.curveName(), label, DidKey.didKey(cert.getPublicKey()));
    }

    @Override
    public byte[] sign(byte[] data) {
        try {
            return sign(session, data);
        } catch (GeneralSecurityException | RuntimeException first) {
            // The token connection may have gone (for example the signer process restarted).
            LOG.warn("PKCS#11 signing failed ({}); reconnecting to {}", rootMessage(first), config.moduleDescription());
            try {
                Session s = connect(config, false, true);
                if ( !Arrays.equals(s.publicKey().getEncoded(), publicKey.getEncoded()) )
                    throw new IllegalStateException("The PKCS#11 key '" + config.keyLabel() + "' changed while the server was running");
                session = s;
                return sign(s, data);
            } catch (GeneralSecurityException | RuntimeException again) {
                again.addSuppressed(first);
                throw new IllegalStateException("PKCS#11 signing failed: " + rootMessage(again), again);
            }
        }
    }

    private byte[] sign(Session s, byte[] data) throws GeneralSecurityException {
        Signature sig = Signature.getInstance(keyType.signatureAlgorithm(), s.provider());
        sig.initSign(s.privateKey());
        sig.update(data);
        return sig.sign();
    }

    @Override
    public String kind() {
        return "pkcs11";
    }

    @Override
    public String description() {
        return "PKCS#11 key '" + config.keyLabel() + "' (" + keyType.curveName() + ") via " + config.moduleDescription();
    }

    @Override
    public PublicKey publicKey() {
        return publicKey;
    }

    @Override
    public KeyType keyType() {
        return keyType;
    }

    private static String rootMessage(Throwable t) {
        Throwable r = t;
        while ( r.getCause() != null && r.getCause() != r )
            r = r.getCause();
        String m = r.getMessage();
        return m == null || m.isBlank() ? r.getClass().getSimpleName() : (r == t ? m : t.getMessage() + ": " + m);
    }

    /** The built-in provider for {@code pkcs11}. */
    public static final class Factory implements SignerProvider {
        @Override
        public String name() {
            return "pkcs11";
        }

        @Override
        public ProvenanceSigner open(SignerSettings settings) {
            return Pkcs11Signer.open(settings);
        }
    }
}

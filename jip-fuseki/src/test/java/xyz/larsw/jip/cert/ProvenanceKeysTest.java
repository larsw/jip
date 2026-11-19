package xyz.larsw.jip.cert;

import static org.junit.jupiter.api.Assertions.*;

import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.spec.ECGenParameterSpec;
import java.util.Map;

import org.apache.jena.atlas.json.JSON;
import org.apache.jena.atlas.json.JsonObject;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** Choosing the signer, and the published forms of P-256/P-384 keys. */
class ProvenanceKeysTest {

    @TempDir
    Path tmp;

    @Test
    void pkcs11IsTheDefaultAndExplainsWhatIsMissing() {
        IllegalStateException ex = assertThrows(IllegalStateException.class, () -> ProvenanceKeys.open(SignerSettings.of(Map.of())));
        assertTrue(ex.getMessage().contains(Pkcs11Signer.ENV_LIBRARY), ex.getMessage());
        assertTrue(ex.getMessage().contains(ProvenanceKeys.ENV_SIGNER + "=local"), ex.getMessage());
    }

    @Test
    void localSignerIsOptIn() {
        Path file = tmp.resolve("key.pem");
        ProvenanceSigner s = ProvenanceKeys.open(SignerSettings.of(Map.of(ProvenanceKeys.ENV_SIGNER, "local",
                                                                          ProvenanceKeys.ENV_KEY_FILE, file.toString())));
        assertEquals("local", s.kind());
        assertEquals(KeyType.ED25519, s.keyType());
        assertTrue(s.didKey().startsWith("did:key:z6Mk"));
        assertTrue(s.description().contains(file.toString()));
        assertEquals(s.didKey(), ProvenanceKeys.open(SignerSettings.of(Map.of(ProvenanceKeys.ENV_SIGNER, "local",
                                                                              ProvenanceKeys.ENV_KEY_FILE, file.toString()))).didKey(),
                     "generated once, then loaded");
    }

    @Test
    void unknownSignerListsTheAvailableOnes() {
        IllegalStateException ex = assertThrows(IllegalStateException.class,
                () -> ProvenanceKeys.open(SignerSettings.of(Map.of(ProvenanceKeys.ENV_SIGNER, "kms"))));
        assertTrue(ex.getMessage().contains("pkcs11") && ex.getMessage().contains("local"), ex.getMessage());
    }

    @Test
    void generateSettingMustBeAnEcCurve() {
        IllegalStateException ex = assertThrows(IllegalStateException.class, () -> Pkcs11Signer.config(SignerSettings.of(Map.of(
                Pkcs11Signer.ENV_LIBRARY, "/nonexistent.so", Pkcs11Signer.ENV_GENERATE, "Ed25519"))));
        assertTrue(ex.getMessage().contains("P-256 or P-384"));
        assertThrows(IllegalArgumentException.class, () -> Pkcs11Signer.config(SignerSettings.of(Map.of(
                Pkcs11Signer.ENV_LIBRARY, "/nonexistent.so", Pkcs11Signer.ENV_GENERATE, "P-512"))));
    }

    @Test
    void missingModuleIsReportedClearly() {
        IllegalStateException ex = assertThrows(IllegalStateException.class, () -> ProvenanceKeys.open(SignerSettings.of(Map.of(
                Pkcs11Signer.ENV_LIBRARY, tmp.resolve("missing-module.so").toString()))));
        assertTrue(ex.getMessage().contains("missing-module.so"), ex.getMessage());
    }

    @Test
    void pinFromFile() throws Exception {
        Path pin = tmp.resolve("pin");
        java.nio.file.Files.writeString(pin, "s3cret\n");
        Pkcs11Signer.Config c = Pkcs11Signer.config(SignerSettings.of(Map.of(Pkcs11Signer.ENV_LIBRARY, "/x.so",
                                                                             Pkcs11Signer.ENV_PIN_FILE, pin.toString())));
        assertArrayEquals("s3cret".toCharArray(), c.pin());
        assertEquals(Pkcs11Signer.DEFAULT_KEY_LABEL, c.keyLabel());
    }

    @Test
    void ecKeysArePublishedAsDidKeyJwkAndPem() throws Exception {
        for ( KeyType type : new KeyType[] { KeyType.P256, KeyType.P384 } ) {
            KeyPairGenerator g = KeyPairGenerator.getInstance("EC");
            g.initialize(new ECGenParameterSpec(type.jcaCurve()));
            KeyPair kp = g.generateKeyPair();
            ProvenanceSigner s = new ProvenanceSigner() {
                @Override
                public String kind() {
                    return "test";
                }

                @Override
                public String description() {
                    return "test";
                }

                @Override
                public PublicKey publicKey() {
                    return kp.getPublic();
                }

                @Override
                public byte[] sign(byte[] data) {
                    throw new UnsupportedOperationException();
                }
            };
            assertEquals(type, s.keyType());
            assertEquals(type.cryptosuite(), KeyType.ECDSA_RDFC_2019);
            assertTrue(s.didKey().startsWith(type == KeyType.P256 ? "did:key:zDn" : "did:key:z82"), s.didKey());
            assertEquals(kp.getPublic(), DidKey.resolve(s.verificationMethod()).publicKey());
            JsonObject jwk = JSON.parse(s.jwk());
            assertEquals("EC", jwk.get("kty").getAsString().value());
            assertEquals(type.curveName(), jwk.get("crv").getAsString().value());
            int coordinate = type == KeyType.P256 ? 32 : 48;
            assertEquals(coordinate, java.util.Base64.getUrlDecoder().decode(jwk.get("x").getAsString().value()).length);
            assertEquals(coordinate, java.util.Base64.getUrlDecoder().decode(jwk.get("y").getAsString().value()).length);
            assertTrue(s.publicPem().startsWith("-----BEGIN PUBLIC KEY-----\n"));
        }
    }
}

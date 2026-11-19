package xyz.larsw.jip.attestation;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.AlgorithmParameters;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.util.Base64;
import java.util.LinkedHashSet;
import java.util.Set;

import org.apache.jena.atlas.json.JSON;
import org.apache.jena.atlas.json.JsonArray;
import org.apache.jena.atlas.json.JsonObject;
import org.apache.jena.atlas.json.JsonValue;

/**
 * Keys a verifier trusts, read from a JWK Set (RFC 7517) such as the server's
 * {@code GET /$/provenance/keys}: the current signing key and the retired ones, so that
 * attestations signed before a key rollover still verify.
 * <p>
 * Each JWK is turned into a {@code did:key} from its key material ({@code kty}, {@code crv},
 * {@code x}, {@code y}); the {@code kid} and other members are not trusted for this. Supported:
 * {@code OKP}/{@code Ed25519} and {@code EC}/{@code P-256}, {@code P-384}.
 */
public final class TrustedKeys {
    private TrustedKeys() {}

    /** The {@code did:key}s of the keys in a JWK Set file. */
    public static Set<String> fromJwkSet(Path file) {
        try {
            return fromJwkSet(Files.readString(file));
        } catch (IOException ex) {
            throw new UncheckedIOException(file.toString(), ex);
        }
    }

    /** The {@code did:key}s of the keys in a JWK Set. */
    public static Set<String> fromJwkSet(String json) {
        JsonObject set;
        try {
            set = JSON.parse(json);
        } catch (RuntimeException ex) {
            throw new IllegalArgumentException("Not a JWK Set: " + ex.getMessage(), ex);
        }
        JsonValue keys = set.get("keys");
        if ( keys == null || !keys.isArray() )
            throw new IllegalArgumentException("Not a JWK Set: no \"keys\" array");
        Set<String> out = new LinkedHashSet<>();
        for ( JsonValue k : (JsonArray)keys ) {
            if ( k.isObject() )
                out.add(DidKey.didKey(publicKey(k.getAsObject())));
        }
        if ( out.isEmpty() )
            throw new IllegalArgumentException("The JWK Set has no keys");
        return Set.copyOf(out);
    }

    /** The public key of one JWK. */
    public static PublicKey publicKey(JsonObject jwk) {
        String kty = string(jwk, "kty");
        String crv = string(jwk, "crv");
        try {
            if ( kty.equals("OKP") && crv.equals("Ed25519") ) {
                byte[] raw = b64(jwk, "x");
                return KeyFactory.getInstance("Ed25519").generatePublic(new java.security.spec.X509EncodedKeySpec(DidKey.toSpki(raw)));
            }
            if ( kty.equals("EC") ) {
                KeyType type = KeyType.parseCurve(crv);
                if ( !type.isEcdsa() )
                    throw new IllegalArgumentException("Unsupported EC curve " + crv);
                AlgorithmParameters params = AlgorithmParameters.getInstance("EC");
                params.init(new ECGenParameterSpec(type.jcaCurve()));
                ECPoint w = new ECPoint(new BigInteger(1, b64(jwk, "x")), new BigInteger(1, b64(jwk, "y")));
                return KeyFactory.getInstance("EC").generatePublic(new ECPublicKeySpec(w, params.getParameterSpec(ECParameterSpec.class)));
            }
        } catch (GeneralSecurityException ex) {
            throw new IllegalArgumentException("Bad " + kty + " key: " + ex.getMessage(), ex);
        }
        throw new IllegalArgumentException("Unsupported JWK: kty " + kty + ", crv " + crv);
    }

    private static String string(JsonObject jwk, String member) {
        JsonValue v = jwk.get(member);
        if ( v == null || !v.isString() )
            throw new IllegalArgumentException("JWK without \"" + member + "\"");
        return v.getAsString().value();
    }

    private static byte[] b64(JsonObject jwk, String member) {
        try {
            return Base64.getUrlDecoder().decode(string(jwk, member));
        } catch (IllegalArgumentException ex) {
            throw new IllegalArgumentException("JWK member \"" + member + "\" is not base64url", ex);
        }
    }
}

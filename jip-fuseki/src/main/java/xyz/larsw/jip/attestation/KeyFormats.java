package xyz.larsw.jip.attestation;

import java.io.IOException;
import java.io.StringWriter;
import java.io.UncheckedIOException;
import java.math.BigInteger;
import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.util.Arrays;
import java.util.Base64;

import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemWriter;

/** JWK and PEM forms of public keys. */
final class KeyFormats {
    private KeyFormats() {}

    static String jwk(PublicKey key) {
        KeyType type = DidKey.keyType(key);
        Base64.Encoder b64 = Base64.getUrlEncoder().withoutPadding();
        if ( type == KeyType.ED25519 ) {
            byte[] raw = DidKey.fromSpki(key.getEncoded());
            return "{\"kty\":\"OKP\",\"crv\":\"Ed25519\",\"x\":\"" + b64.encodeToString(raw) + "\"}";
        }
        ECPublicKey ec = (ECPublicKey)key;
        int len = (ec.getParams().getCurve().getField().getFieldSize() + 7) / 8;
        return "{\"kty\":\"EC\",\"crv\":\"" + type.curveName() + "\",\"x\":\"" + b64.encodeToString(fixed(ec.getW().getAffineX(), len))
               + "\",\"y\":\"" + b64.encodeToString(fixed(ec.getW().getAffineY(), len)) + "\"}";
    }

    static String pem(PublicKey key) {
        return pem(new PemObject("PUBLIC KEY", key.getEncoded()));
    }

    static String pem(PemObject object) {
        StringWriter out = new StringWriter();
        try ( PemWriter w = new PemWriter(out) ) {
            w.writeObject(object);
        } catch (IOException ex) {
            throw new UncheckedIOException(ex);
        }
        return out.toString().replace("\r\n", "\n");
    }

    /** Unsigned big-endian, left-padded to {@code len} bytes (JWK coordinates, RFC 7518 §6.2.1). */
    private static byte[] fixed(BigInteger n, int len) {
        byte[] b = n.toByteArray();
        if ( b.length == len )
            return b;
        if ( b.length > len )
            return Arrays.copyOfRange(b, b.length - len, b.length);
        byte[] out = new byte[len];
        System.arraycopy(b, 0, out, len - b.length, b.length);
        return out;
    }
}

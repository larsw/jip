package xyz.larsw.jip.attestation;

import java.io.ByteArrayOutputStream;
import java.math.BigInteger;

/** Base58 with the Bitcoin alphabet, as used by multibase {@code z} (base58btc). */
public final class Base58 {
    private Base58() {}

    private static final String ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    private static final BigInteger BASE = BigInteger.valueOf(58);

    public static String encode(byte[] input) {
        BigInteger n = new BigInteger(1, input);
        StringBuilder sb = new StringBuilder();
        while ( n.signum() > 0 ) {
            BigInteger[] qr = n.divideAndRemainder(BASE);
            sb.append(ALPHABET.charAt(qr[1].intValue()));
            n = qr[0];
        }
        for ( int i = 0 ; i < input.length && input[i] == 0 ; i++ )
            sb.append(ALPHABET.charAt(0));
        return sb.reverse().toString();
    }

    public static byte[] decode(String input) {
        BigInteger n = BigInteger.ZERO;
        for ( int i = 0 ; i < input.length() ; i++ ) {
            int digit = ALPHABET.indexOf(input.charAt(i));
            if ( digit < 0 )
                throw new IllegalArgumentException("Invalid base58 character: '" + input.charAt(i) + "'");
            n = n.multiply(BASE).add(BigInteger.valueOf(digit));
        }
        byte[] bytes = n.toByteArray();
        // BigInteger may add a sign byte.
        int strip = (bytes.length > 1 && bytes[0] == 0) ? 1 : 0;
        if ( n.signum() == 0 )
            strip = bytes.length;
        int leadingZeros = 0;
        while ( leadingZeros < input.length() && input.charAt(leadingZeros) == ALPHABET.charAt(0) )
            leadingZeros++;
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(new byte[leadingZeros], 0, leadingZeros);
        out.write(bytes, strip, bytes.length - strip);
        return out.toByteArray();
    }

    /** Multibase base58btc: {@code 'z' + base58}. */
    public static String encodeMultibase(byte[] input) {
        return "z" + encode(input);
    }

    public static byte[] decodeMultibase(String multibase) {
        if ( multibase == null || !multibase.startsWith("z") )
            throw new IllegalArgumentException("Not a base58btc multibase value (expected 'z' prefix)");
        return decode(multibase.substring(1));
    }
}

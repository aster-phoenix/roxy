package xyz.pretsa.roxy.converter;

import java.math.BigInteger;
import java.util.Base64;

/**
 *
 * @author ghazy
 */
public class Converters {

    public static String toBase64(byte[] array) {
        return Base64.getEncoder().encodeToString(array);
    }

    public static byte[] fromBase64(String encodedArray) {
        return Base64.getDecoder().decode(encodedArray);
    }

    public static String toHex(byte[] array) {
        BigInteger bi = new BigInteger(1, array);
        String hex = bi.toString(16);
        int paddingLength = (array.length * 2) - hex.length();
        if (paddingLength > 0) {
            return String.format("%0" + paddingLength + "d", 0) + hex;
        } else {
            return hex;
        }
    }

    public static String fromHex(byte[] bytes) {
        throw new RuntimeException("Not Implemented yet");
    }
}

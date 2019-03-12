package xyz.pretsa.roxy.converter;

import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.util.Base64;

/**
 *
 * @author ghazy
 */
public class Converters {
    
    private static final String UTF_8 = "UTF-8";
    
    public static String bytesToString(byte[] array) {
        return new String(array);
    }
    
    public static byte[] stringToBytes(String string) throws UnsupportedEncodingException {
        return string.getBytes(UTF_8);
    }

    public static String bytesToBase64(byte[] array) {
        return Base64.getEncoder().encodeToString(array);
    }

    public static byte[] base64ToBytes(String encodedArray) {
        return Base64.getDecoder().decode(encodedArray);
    }

    public static String bytesToHex(byte[] array) {
        BigInteger bi = new BigInteger(1, array);
        String hex = bi.toString(16);
        int paddingLength = (array.length * 2) - hex.length();
        if (paddingLength > 0) {
            return String.format("%0" + paddingLength + "d", 0) + hex;
        } else {
            return hex;
        }
    }

    public static byte[] HexToBytes(String encodedArray) {
        throw new RuntimeException("Not Implemented yet");
    }
}

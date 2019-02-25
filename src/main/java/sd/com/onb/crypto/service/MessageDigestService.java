package sd.com.onb.crypto.service;

import java.io.UnsupportedEncodingException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 *
 * @author Ghazy
 */
public class MessageDigestService {

    public static byte[] hash(String message, String algorithm) throws NoSuchAlgorithmException, UnsupportedEncodingException {
        MessageDigest md = MessageDigest.getInstance(algorithm);
        byte[] digest = md.digest(message.getBytes("UTF-8"));
        return digest;
    }
    
}

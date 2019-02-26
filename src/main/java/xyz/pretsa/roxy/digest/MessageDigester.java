package xyz.pretsa.roxy.digest;

import java.io.UnsupportedEncodingException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

/**
 *
 * @author Ghazy
 */
public class MessageDigester {

    public String hash(String message, String algorithm) throws NoSuchAlgorithmException, UnsupportedEncodingException {
        MessageDigest md = MessageDigest.getInstance(algorithm);
        byte[] digestArray = md.digest(message.getBytes("UTF-8"));
        return Base64.getEncoder().encodeToString(digestArray);
    }
    
}

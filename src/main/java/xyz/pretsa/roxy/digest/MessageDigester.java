package xyz.pretsa.roxy.digest;

import java.io.UnsupportedEncodingException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

/**
 *
 * @author Ghazy
 */
public class MessageDigester {
    
    private final String PBKDF2_ALGORITHM = "PBKDF2WithHmacSHA1";
    private final int DEFAULT_PBKDF2_ITERATIONS = 10_000;
    private final int DEFAULT_PBKDF2_KEY_SIZE = 128;

    protected byte[] hash(byte[] message, String algorithm) throws NoSuchAlgorithmException, UnsupportedEncodingException {
        MessageDigest md = MessageDigest.getInstance(algorithm);
        byte[] hash = md.digest(message);
        return hash;
    }
    
    protected byte[] hash(byte[] message, byte[] salt, String algorithm) throws NoSuchAlgorithmException, UnsupportedEncodingException {
        MessageDigest md = MessageDigest.getInstance(algorithm);
        md.update(salt);
        byte[] hash = md.digest(message);
        return hash;
    }
    
    protected byte[] PBKDF2Hash(char[] message, byte[] salt) throws InvalidKeySpecException, NoSuchAlgorithmException {
        return PBKDF2Hash(message, salt, DEFAULT_PBKDF2_KEY_SIZE);
    }
    
    protected byte[] PBKDF2Hash(char[] message, byte[] salt, int keySize) throws InvalidKeySpecException, NoSuchAlgorithmException {
        return PBKDF2Hash(message, salt, DEFAULT_PBKDF2_ITERATIONS, keySize);
    }
    
    protected byte[] PBKDF2Hash(char[] message, byte[] salt, int iterations, int keySize) throws InvalidKeySpecException, NoSuchAlgorithmException {
        PBEKeySpec spec = new PBEKeySpec(message, salt, iterations, keySize);
        SecretKeyFactory skf = SecretKeyFactory.getInstance(PBKDF2_ALGORITHM);
        byte[] hash = skf.generateSecret(spec).getEncoded();
        return hash;
    }

}

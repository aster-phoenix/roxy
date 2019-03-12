package xyz.pretsa.roxy.digest;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

/**
 *
 * @author ghazy
 */
public class SaltBuilder {
    
    private static final int DEFAULT_SALT_SIZE = 16;
    private static final String DEFAULT_SALT_ALGORITHM = "SHA1PRNG";
    
    public static byte[] random16BytesSalt() throws NoSuchAlgorithmException {
        SecureRandom sr = SecureRandom.getInstance(DEFAULT_SALT_ALGORITHM);
        byte[] salt = new byte[DEFAULT_SALT_SIZE];
        sr.nextBytes(salt);
        return salt;
    }
    
}

package xyz.pretsa.roxy.digest;

import java.io.UnsupportedEncodingException;
import java.security.NoSuchAlgorithmException;
import org.junit.Test;
import static org.junit.Assert.*;
import xyz.pretsa.roxy.converter.Converters;

/**
 *
 * @author ghazy
 */
public class MessageDigestFacadeTest {

    private final String message = "ROXY";
    private final String md5HashedMessage = "IRfMxVOQnOMb+Ca5AHvwnA==";
    private final String sha256HashedMessage = "po5tpDDg2uwP5oQXy4evMdHw6JTdFRw+avjqB2j5evM=";
    private final String sha384HashedMessage = "GLu9z3kBKgxLZN7l+c2nEclPV5cdFJR6GbwQAxs3e+6fzjcOjy1HsTutaroQmgca";
    private final String sha512HashedMessage = "UL/Clr+LIRkn+cX5HxEWuuWtXZVTrtkCg5JH/MaZfWk5JMrUSGEKp64ljsXRFAUg3Amoi9c2ltbfiM0a0uCOxQ==";

    private final MessageDigestFacade instance;

    public MessageDigestFacadeTest() throws NoSuchAlgorithmException {
        instance = new MessageDigestFacade();
    }

    /**
     * Test of hashWithMd5AsString method, of class MessageDigestFacade.
     *
     * @throws java.lang.Exception
     */
    @Test
    public void testHashWithMd5AsString() throws Exception {
        System.out.println("hashWithMd5AsString");
        String result = instance.hashWithMd5AsString(message);
        assertEquals(md5HashedMessage, result);
    }


    /**
     * Test of hashWithSha256AsString method, of class MessageDigestFacade.
     *
     * @throws java.lang.Exception
     */
    @Test
    public void testHashWithSha256AsString() throws Exception {
        System.out.println("hashWithSha256AsString");
        String result = instance.hashWithSha256AsString(message);
        assertEquals(sha256HashedMessage, result);
    }


    /**
     * Test of hashWithSha384 method, of class MessageDigestFacade.
     *
     * @throws java.lang.Exception
     */
    @Test
    public void testHashWithSha384AsString() throws Exception {
        System.out.println("hashWithSha384AsString");
        String result = instance.hashWithSha384AsString(message);
        assertEquals(sha384HashedMessage, result);
    }


    /**
     * Test of hashWithSha512AsString method, of class MessageDigestFacade.
     *
     * @throws java.lang.Exception
     */
    @Test
    public void testHashWithSha512AsString() throws Exception {
        System.out.println("hashWithSha512AsString");
        String result = instance.hashWithSha512AsString(message);
        assertEquals(sha512HashedMessage, result);
    }



    /**
     * Test of hashWithPBKDF2AsString method, of class MessageDigestFacade.
     *
     * @throws java.lang.Exception
     */
    @Test
    public void testHashWithPBKDF2AsStringWithIterations() throws Exception {
        System.out.println("hashWithPBKDF2AsStringWithIterations");
        byte[] salt = SaltBuilder.random16BytesSalt();
        int iterations = 1000;
        int keySize = 128;
        byte[] result = instance.hashWithPBKDF2(message.toCharArray(), salt, iterations, keySize);
        assertEquals(16, result.length);
    }
    
    @Test
    public void testHashWithPBKDF2() throws Exception {
        System.out.println("hashWithPBKDF2");
        byte[] salt = SaltBuilder.random16BytesSalt();
        byte[] result1 = instance.hashWithPBKDF2(message.toCharArray(), salt);
        byte[] result2 = instance.hashWithPBKDF2(message.toCharArray(), salt);
        String hash1 = Converters.bytesToBase64(result1);
        String hash2 = Converters.bytesToBase64(result2);
        String hash3 = instance.hashWithPBKDF2AsString(message, salt);
        assertEquals(hash1, hash2);
        assertEquals(hash1, hash3);
        
    }
    
    @Test
    public void testSaltBuilder() throws Exception {
        byte[] saltBytes1 = SaltBuilder.random16BytesSalt();
        String saltString1 = Converters.bytesToBase64(saltBytes1);
        byte[] saltBytes2 = SaltBuilder.existingSalt(saltString1);
        String saltString2 = Converters.bytesToBase64(saltBytes2);
        assertEquals(saltString1, saltString2);
    }

}

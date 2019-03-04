package xyz.pretsa.roxy.asymmetric;

import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import org.junit.Before;
import org.junit.Test;
import static org.junit.Assert.*;

/**
 *
 * @author ghazy
 */
public class RSACipherFacadeTest {
    
    RSACipherFacade facade;
    
    @Before
    public void setUp() throws NoSuchAlgorithmException {
        facade = new RSACipherFacade();
    }

    /**
     * Test of encryptString method, of class RSACipherFacade.
     */
    @Test
    public void testRSAEncryptionDecriptionWithDefaultKeychain() {
        try {
            RSAKeychain keyChain = RSAKeychainBuilder.withNewKeyPair();
            String original = "Ghazy";
            String encryptedString = facade.encryptString(original, keyChain);
            String decryptedString = facade.decryptString(encryptedString, keyChain);
            assertEquals(decryptedString, original);
        } catch (Exception e) {
            e.printStackTrace();
            fail(e.getMessage());
        }
    }
    
    @Test
    public void testRSAEncryptionDecriptionWithExistingStringKeys() {
        try {
            RSAKeychain keyChain = RSAKeychainBuilder.withNewKeyPair();
            byte[] publicKeyBytes = RSAKeychainBuilder.encodePublicKey(keyChain.getPublicKey());
            byte[] privateKeyBytes = RSAKeychainBuilder.encodePrivateKey(keyChain.getPrivateKey());
            
            String publicKey = Base64.getEncoder().encodeToString(publicKeyBytes);
            String privateKey = Base64.getEncoder().encodeToString(privateKeyBytes);
            
            keyChain = RSAKeychainBuilder.withExistingKeys(publicKey, privateKey);
            String original = "Ghazy";
            String encryptedString = facade.encryptString(original, keyChain);
            String decryptedString = facade.decryptString(encryptedString, keyChain);
            assertEquals(decryptedString, original);
        } catch (Exception e) {
            e.printStackTrace();
            fail(e.getMessage());
        }
    }
    
}

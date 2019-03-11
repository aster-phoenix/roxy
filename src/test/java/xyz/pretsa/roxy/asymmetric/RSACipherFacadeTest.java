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
            String encryptedString = facade.encryp(original, keyChain);
            String decryptedString = facade.decryp(encryptedString, keyChain);
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
            
            String stringPublicKey = keyChain.getEncodePublicKeyAsString();
            String stringPrivateKey = keyChain.getEncodePrivateKeyAsString();
            
            keyChain = RSAKeychainBuilder.withExistingKeys(stringPublicKey, stringPrivateKey);
            String original = "Ghazy";
            String encryptedString = facade.encryp(original, keyChain);
            String decryptedString = facade.decryp(encryptedString, keyChain);
            assertEquals(decryptedString, original);
        } catch (Exception e) {
            e.printStackTrace();
            fail(e.getMessage());
        }
    }
    
}

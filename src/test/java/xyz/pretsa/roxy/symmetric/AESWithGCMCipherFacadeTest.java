package xyz.pretsa.roxy.symmetric;

import java.util.Base64;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import static org.junit.Assert.*;

/**
 *
 * @author ghazy
 */
public class AESWithGCMCipherFacadeTest {

    AESWithGCMCipherFacade facade;

    @Before
    public void setUp() {
        facade = new AESWithGCMCipherFacade();
    }

    @After
    public void tearDown() {
    }

    @Test
    public void testAESEncryptionDecriptionWithMinimalKeychain() {
        try {
            AESWithGCMKeychain keyChain = AESWithGCMKeychainBuilder.newMinimalKeychain();
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
    public void testAESEncryptionDecriptionWithExistingKeychain() {
        try {
            AESWithGCMKeychain keyChain = AESWithGCMKeychainBuilder.newMinimalKeychain();
            
            String secretKey = Base64.getEncoder().encodeToString(keyChain.getSecretKey().getEncoded());
            String gcm = Base64.getEncoder().encodeToString(keyChain.getGcm().getIV());
            String aad = Base64.getEncoder().encodeToString(keyChain.getAad());
            
            keyChain = AESWithGCMKeychainBuilder.withExistingKeys(secretKey, keyChain.getGcm().getIV().length, gcm, aad);
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

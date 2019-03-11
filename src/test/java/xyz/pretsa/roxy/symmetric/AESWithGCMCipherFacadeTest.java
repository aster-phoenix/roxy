package xyz.pretsa.roxy.symmetric;

import java.util.Arrays;
import java.util.Base64;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import static org.junit.Assert.*;
import xyz.pretsa.roxy.digest.MessageDigestFacade;

/**
 *
 * @author ghazy
 */
public class AESWithGCMCipherFacadeTest {

    AESWithGCMCipherFacade AESFacade;
    MessageDigestFacade digestFacade;

    @Before
    public void setUp() {
        AESFacade = new AESWithGCMCipherFacade();
        digestFacade = new MessageDigestFacade();
    }

    @After
    public void tearDown() {
    }

    @Test
    public void testAESEncryptionDecriptionWithMinimalKeychain() {
        try {
            AESWithGCMKeychain keyChain = AESWithGCMKeychainBuilder.withNewKeychain();
            String original = "Ghazy";
            String encryptedString = AESFacade.encrypt(original, keyChain);
            String decryptedString = AESFacade.decrypt(encryptedString, keyChain);
            assertEquals(decryptedString, original);
        } catch (Exception e) {
            e.printStackTrace();
            fail(e.getMessage());
        }
    }

    @Test
    public void testAESEncryptionDecriptionWithExistingKeychain() {
        try {
            AESWithGCMKeychain keyChain = AESWithGCMKeychainBuilder.withNewKeychain();

            String secretKeyString = keyChain.getEncodedSecretKeyAsString();
            String gcmString = keyChain.getEncodedGcmAsString();
            String aadString = keyChain.getEncodedAadAsString();

            keyChain = AESWithGCMKeychainBuilder.withExistingKeys(secretKeyString, 128, gcmString, aadString);
            String original = "Ghazy";
            String encryptedString = AESFacade.encrypt(original, keyChain);
            String decryptedString = AESFacade.decrypt(encryptedString, keyChain);
            assertEquals(decryptedString, original);
        } catch (Exception e) {
            e.printStackTrace();
            fail(e.getMessage());
        }
    }

    @Test
    public void testAESEncryptionDecriptionWithCustomKeychain() {
        try {
            AESWithGCMKeychain keyChain = AESWithGCMKeychainBuilder.withNewKeychain();
            String myCustomSecret = "passphrase";
            byte[] hashedCustomKey = digestFacade.hashWithSha256(myCustomSecret);
            keyChain = AESWithGCMKeychainBuilder.withExistingKeys(hashedCustomKey, 128, keyChain.getEncodedGcm(), keyChain.getAad());
            String original = "Ghazy";
            String encryptedString = AESFacade.encrypt(original, keyChain);
            String decryptedString = AESFacade.decrypt(encryptedString, keyChain);
            assertEquals(decryptedString, original);
        } catch (Exception e) {
            e.printStackTrace();
            fail(e.getMessage());
        }
    }

}

package xyz.pretsa.roxy.symmetric;

import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import org.junit.Test;
import static org.junit.Assert.*;
import xyz.pretsa.roxy.digest.MessageDigestFacade;
import xyz.pretsa.roxy.digest.SaltBuilder;

/**
 *
 * @author ghazy
 */
public class AESWithGCMCipherFacadeTest {

    private final String original = "ROXY";
    private final String password = "PASSWORD";

    private final AESWithGCMCipherFacade AESFacade;
    private final MessageDigestFacade digestFacade;
    private AESWithGCMKeychain keychain;

    public AESWithGCMCipherFacadeTest() throws NoSuchAlgorithmException {
        AESFacade = new AESWithGCMCipherFacade();
        digestFacade = new MessageDigestFacade();
    }

    @Test
    public void testAESEncryptionDecriptionWithNewKeychain() throws NoSuchAlgorithmException, InvalidKeyException, InvalidAlgorithmParameterException, NoSuchPaddingException, UnsupportedEncodingException, IllegalBlockSizeException, BadPaddingException {
        keychain = AESWithGCMKeychainBuilder.withNewKeychain();
        String encryptedString = AESFacade.encrypt(original, keychain);
        String decryptedString = AESFacade.decrypt(encryptedString, keychain);
        assertEquals(decryptedString, original);
    }

    @Test
    public void testAESEncryptionDecriptionWithCustomKeychain() throws NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException, InvalidAlgorithmParameterException, NoSuchPaddingException, UnsupportedEncodingException, IllegalBlockSizeException, BadPaddingException {
        keychain = AESWithGCMKeychainBuilder.withNewKeychain();
        byte[] hashedCustomKey = digestFacade.hashWithPBKDF2(password.toCharArray(), SaltBuilder.random16BytesSalt());
        keychain = AESWithGCMKeychainBuilder.withExistingEncodedKeys(hashedCustomKey, 128, keychain.getEncodedGcm(), keychain.getAad());
        String encryptedString = AESFacade.encrypt(original, keychain);
        String decryptedString = AESFacade.decrypt(encryptedString, keychain);
        assertEquals(decryptedString, original);
    }

}
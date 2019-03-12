package xyz.pretsa.roxy.asymmetric;

import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import org.junit.Test;
import static org.junit.Assert.*;

/**
 *
 * @author ghazy
 */
public class RSACipherFacadeTest {
    
    private final String original = "ROXY";

    private final RSACipherFacade instance;
    private RSAKeychain keyChain;

    public RSACipherFacadeTest() {
        instance = new RSACipherFacade();
    }

    /**
     * Test of encryptString method, of class RSACipherFacade.
     */
    @Test
    public void testRSAEncryptionDecriptionWithNewKeychain() throws NoSuchAlgorithmException, InvalidKeyException, UnsupportedEncodingException, IllegalBlockSizeException, NoSuchPaddingException, BadPaddingException {
        keyChain = RSAKeychainBuilder.withNewKeychain();
        String encryptedString = instance.encryp(original, keyChain);
        String decryptedString = instance.decryp(encryptedString, keyChain);
        assertEquals(decryptedString, original);
    }

}

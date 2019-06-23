package xyz.pretsa.roxy.asymmetric;

import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import org.junit.Test;
import static org.junit.Assert.*;
import xyz.pretsa.roxy.converter.Converters;
import xyz.pretsa.roxy.digest.MessageDigestFacade;
import xyz.pretsa.roxy.digest.SaltBuilder;
import xyz.pretsa.roxy.symmetric.AESWithGCMCipherFacade;
import xyz.pretsa.roxy.symmetric.AESWithGCMKeychain;
import xyz.pretsa.roxy.symmetric.AESWithGCMKeychainBuilder;

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

    @Test
    public void testRSAEncryptionDecriptionWithCustomEncodedKey() throws Exception {
        String masterPassword = "orca";
        String secret = "skua";
        AESWithGCMCipherFacade aesCipher = new AESWithGCMCipherFacade();
        // Create AES key based on MATER PASSWORD
        byte[] salt = SaltBuilder.random16BytesSalt();
        MessageDigestFacade digestFacade = new MessageDigestFacade();
        byte[] masterKey = digestFacade.hashWithPBKDF2(masterPassword.toCharArray(), salt);

        // Create AES Keychain
        AESWithGCMKeychain aesKeychain = AESWithGCMKeychainBuilder.withNewKeychain();
        aesKeychain = AESWithGCMKeychainBuilder.withExistingEncodedKeys(masterKey, 128, aesKeychain.getEncodedGcm(), aesKeychain.getAad());

        String encodedSalt = Converters.bytesToBase64(salt);
        String encodedGcm = aesKeychain.getEncodedGcmAsString();
        String encodedAad = aesKeychain.getEncodedAadAsString();

        // Create RSA Keychain and encrypt the private key 
        RSAKeychain rsaKeychain = RSAKeychainBuilder.withNewKeychain();
        String publicKey = rsaKeychain.getEncodedPublicKeyAsString();
        String EncryptedPrivateKey = aesCipher.encrypt(rsaKeychain.getEncodedPrivateKeyAsString(), aesKeychain);

        RSACipherFacade rsaCipher = new RSACipherFacade();
        rsaKeychain = RSAKeychainBuilder.withExistingEncodedPublicKey(publicKey);
        String encryptedSecret = rsaCipher.encryp(secret, rsaKeychain);

        salt = SaltBuilder.existingSalt(encodedSalt);
        String encodedMasterKey = digestFacade.hashWithPBKDF2AsString(masterPassword, salt);

        // Create AES Keychain
        aesCipher = new AESWithGCMCipherFacade();
        aesKeychain = AESWithGCMKeychainBuilder.withExistingEncodedKeys(encodedMasterKey, 128, encodedGcm, encodedAad);
        String privateKey = aesCipher.decrypt(EncryptedPrivateKey, aesKeychain);

        rsaCipher = new RSACipherFacade();
        rsaKeychain = RSAKeychainBuilder.withExistingEncodedPrivateKey(privateKey);
        String plainSecret = rsaCipher.decryp(encryptedSecret, rsaKeychain);
        System.out.println(plainSecret);
        assertEquals(plainSecret, secret);
    }

}

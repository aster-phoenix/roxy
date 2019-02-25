package xyz.pretsa.roxy.symmetric;

import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

/**
 *
 * @author ghazy
 */
public class AESWithGCMCipherFacade {
    
    private final AESWithGCMCipher cipher;

    public AESWithGCMCipherFacade() {
        this.cipher = new AESWithGCMCipher();
    }
    
    public String encryptString(String plainText, AESWithGCMKeychain keyChain) throws NoSuchAlgorithmException, InvalidKeyException, InvalidAlgorithmParameterException, NoSuchPaddingException, UnsupportedEncodingException, IllegalBlockSizeException, BadPaddingException{
        return cipher.encrypt(plainText, keyChain.getSecretKey(), keyChain.getGcm(), keyChain.getAad());
    }
    
    public  String decryptString(String encryptedString, AESWithGCMKeychain keyChain) throws NoSuchAlgorithmException, InvalidKeyException, InvalidAlgorithmParameterException, NoSuchPaddingException, UnsupportedEncodingException, IllegalBlockSizeException, BadPaddingException {
        return cipher.decrypt(encryptedString, keyChain.getSecretKey(), keyChain.getGcm(), keyChain.getAad());
    }
    
}

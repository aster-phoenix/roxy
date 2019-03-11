package xyz.pretsa.roxy.symmetric;

import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import xyz.pretsa.roxy.converter.Converters;

/**
 *
 * @author ghazy
 */
public class AESWithGCMCipherFacade {
    
    private final String UTF_8 = "UTF-8";
    private final AESWithGCMCipher cipher;

    public AESWithGCMCipherFacade() {
        this.cipher = new AESWithGCMCipher();
    }
    
    // Encrypt
    public String encrypt(String message, AESWithGCMKeychain keyChain) throws NoSuchAlgorithmException, InvalidKeyException, InvalidAlgorithmParameterException, NoSuchPaddingException, UnsupportedEncodingException, IllegalBlockSizeException, BadPaddingException{
        byte[] encryptedMessage = encrypt(message.getBytes(UTF_8), keyChain);
        return Converters.toBase64(encryptedMessage);
    }
    public byte[] encrypt(byte[] message, AESWithGCMKeychain keyChain) throws NoSuchAlgorithmException, InvalidKeyException, InvalidAlgorithmParameterException, NoSuchPaddingException, UnsupportedEncodingException, IllegalBlockSizeException, BadPaddingException{
        return cipher.encrypt(message, keyChain.getSecretKey(), keyChain.getGcm(), keyChain.getAad());
    }
    
    // Decrypt
    public  String decrypt(String encryptedMessage, AESWithGCMKeychain keyChain) throws NoSuchAlgorithmException, InvalidKeyException, InvalidAlgorithmParameterException, NoSuchPaddingException, UnsupportedEncodingException, IllegalBlockSizeException, BadPaddingException {
        byte[] encryptedMessageBytes = Converters.fromBase64(encryptedMessage);
        byte[] decryptedMessage = decrypt(encryptedMessageBytes, keyChain);
        return new String(decryptedMessage);
    }
    public byte[] decrypt(byte[] encryptedMessage, AESWithGCMKeychain keyChain) throws NoSuchAlgorithmException, InvalidKeyException, InvalidAlgorithmParameterException, NoSuchPaddingException, UnsupportedEncodingException, IllegalBlockSizeException, BadPaddingException {
        return cipher.decrypt(encryptedMessage, keyChain.getSecretKey(), keyChain.getGcm(), keyChain.getAad());
    }
    
}

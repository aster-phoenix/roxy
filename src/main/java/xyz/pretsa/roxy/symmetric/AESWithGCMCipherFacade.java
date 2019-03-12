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
    
    private final AESWithGCMCipher cipher;

    public AESWithGCMCipherFacade() {
        this.cipher = new AESWithGCMCipher();
    }
    
    // Encrypt
    public String encrypt(String message, AESWithGCMKeychain keyChain) throws NoSuchAlgorithmException, InvalidKeyException, InvalidAlgorithmParameterException, NoSuchPaddingException, UnsupportedEncodingException, IllegalBlockSizeException, BadPaddingException{
        byte[] messageBytes = Converters.stringToBytes(message);
        byte[] encryptedMessage = encrypt(messageBytes, keyChain);
        return Converters.bytesToBase64(encryptedMessage);
    }
    public byte[] encrypt(byte[] message, AESWithGCMKeychain keyChain) throws NoSuchAlgorithmException, InvalidKeyException, InvalidAlgorithmParameterException, NoSuchPaddingException, UnsupportedEncodingException, IllegalBlockSizeException, BadPaddingException{
        return cipher.encrypt(message, keyChain.getSecretKey(), keyChain.getGcm(), keyChain.getAad());
    }
    
    // Decrypt
    public  String decrypt(String encryptedMessage, AESWithGCMKeychain keyChain) throws NoSuchAlgorithmException, InvalidKeyException, InvalidAlgorithmParameterException, NoSuchPaddingException, UnsupportedEncodingException, IllegalBlockSizeException, BadPaddingException {
        byte[] encryptedMessageBytes = Converters.base64ToBytes(encryptedMessage);
        byte[] decryptedMessage = decrypt(encryptedMessageBytes, keyChain);
        return Converters.bytesToString(decryptedMessage);
    }
    public byte[] decrypt(byte[] encryptedMessage, AESWithGCMKeychain keyChain) throws NoSuchAlgorithmException, InvalidKeyException, InvalidAlgorithmParameterException, NoSuchPaddingException, UnsupportedEncodingException, IllegalBlockSizeException, BadPaddingException {
        return cipher.decrypt(encryptedMessage, keyChain.getSecretKey(), keyChain.getGcm(), keyChain.getAad());
    }
    
}

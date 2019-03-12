package xyz.pretsa.roxy.asymmetric;

import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import xyz.pretsa.roxy.converter.Converters;

/**
 *
 * @author ghazy
 */
public class RSACipherFacade {
    
    private final String SHA512_SIGNATURE_ALGORITHM = "SHA512withRSA";
    private final RSACipher cipher;

    public RSACipherFacade() {
        this.cipher = new RSACipher();
    }
    
    // Encrypt
    public String encryp(String message, RSAKeychain keyChain) throws NoSuchAlgorithmException, InvalidKeyException, UnsupportedEncodingException, IllegalBlockSizeException, BadPaddingException, NoSuchPaddingException{
        byte[] messageBytes = Converters.stringToBytes(message);
        byte[] encryptedMessage = encryp(messageBytes, keyChain);
        return Converters.bytesToBase64(encryptedMessage);
    }
    public byte[] encryp(byte[] message, RSAKeychain keyChain) throws NoSuchAlgorithmException, InvalidKeyException, UnsupportedEncodingException, IllegalBlockSizeException, BadPaddingException, NoSuchPaddingException{
        byte[] encryptedMessage = cipher.encrypt(message, keyChain.getPublicKey());
        return encryptedMessage;
    }
    
    // Decrypt
    public String decryp(String encryptedMessage, RSAKeychain keyChain) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, UnsupportedEncodingException {
        byte[] encryptedMessageBytes = Converters.base64ToBytes(encryptedMessage);
        byte[] decryptedMessage = decryp(encryptedMessageBytes, keyChain);
        return Converters.bytesToString(decryptedMessage);
    }
    public byte[] decryp(byte[] encryptedMessage, RSAKeychain keyChain) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        return cipher.decrypt(encryptedMessage, keyChain.getPrivateKey());
    }
    
    // Sign
    public String signStringMsgWithSHA512(String message, RSAKeychain keyChain) throws NoSuchAlgorithmException, InvalidKeyException, UnsupportedEncodingException, SignatureException {
        byte[] messageBytes = Converters.stringToBytes(message);
        byte[] messageSignature = signStringMsgWithSHA512(messageBytes, keyChain);
        return Converters.bytesToBase64(messageSignature);
    }
    public byte[] signStringMsgWithSHA512(byte[] message, RSAKeychain keyChain) throws NoSuchAlgorithmException, InvalidKeyException, UnsupportedEncodingException, SignatureException {
        return cipher.sign(message, SHA512_SIGNATURE_ALGORITHM, keyChain.getPrivateKey());
    }
    
    // Verify
    public boolean verifySignatureWithSHA512(String message, String messageSignature, RSAKeychain keyChain) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException, UnsupportedEncodingException {
        byte[] messageSignatureBytes = Converters.base64ToBytes(messageSignature);
        byte[] messageBytes = Converters.stringToBytes(message);
        return verifySignatureWithSHA512(messageBytes, messageSignatureBytes, keyChain);
        
    }
    public boolean verifySignatureWithSHA512(byte[] message, byte[] messageSignature, RSAKeychain keyChain) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException, UnsupportedEncodingException {
        return cipher.verify(message, messageSignature, SHA512_SIGNATURE_ALGORITHM, keyChain.getPublicKey());
    }
    
    
}

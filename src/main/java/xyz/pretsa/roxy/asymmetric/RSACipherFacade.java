package xyz.pretsa.roxy.asymmetric;

import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

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
    
    public String encryptString(String plainText, RSAKeychain keyChain) throws NoSuchAlgorithmException, InvalidKeyException, UnsupportedEncodingException, IllegalBlockSizeException, BadPaddingException, NoSuchPaddingException{
        return cipher.encrypt(plainText, keyChain.getPublicKey());
    }
    
    public String decryptString(String encryptedText, RSAKeychain keyChain) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        return cipher.decrypt(encryptedText, keyChain.getPrivateKey());
    }
    
    public String signStringMsgWithSHA512(String msg, RSAKeychain keyChain) throws NoSuchAlgorithmException, InvalidKeyException, UnsupportedEncodingException, SignatureException {
        return cipher.sign(msg, SHA512_SIGNATURE_ALGORITHM, keyChain.getPrivateKey());
    }
    
    public boolean verifySignatureWithSHA512(String msg, String signature, RSAKeychain keyChain) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException, UnsupportedEncodingException {
        return cipher.verify(msg, signature, SHA512_SIGNATURE_ALGORITHM, keyChain.getPublicKey());
    }
    
    
}

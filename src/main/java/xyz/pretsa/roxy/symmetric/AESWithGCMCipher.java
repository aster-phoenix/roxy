package xyz.pretsa.roxy.symmetric;

import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;

/**
 *
 * @author Ghazy
 */
public class AESWithGCMCipher {

    private final String ALGO_TRANSFORMATION_STRING = "AES/GCM/PKCS5Padding";

    public String encrypt(String message, SecretKey aesKey, GCMParameterSpec gcmParamSpec, byte[] aad) throws NoSuchAlgorithmException, InvalidKeyException, InvalidAlgorithmParameterException, NoSuchPaddingException, UnsupportedEncodingException, IllegalBlockSizeException, BadPaddingException {
        Cipher c = Cipher.getInstance(ALGO_TRANSFORMATION_STRING); // Transformation specifies algortihm, mode of operation and padding
        c.init(Cipher.ENCRYPT_MODE, aesKey, gcmParamSpec, new SecureRandom());
        c.updateAAD(aad); // add AAD tag data before encrypting
        byte[] encryptedTextArray = c.doFinal(message.getBytes("UTF-8"));
        return Base64.getEncoder().encodeToString(encryptedTextArray);
    }

    public String decrypt(String encryptedText, SecretKey aesKey, GCMParameterSpec gcmParamSpec, byte[] aadData) throws NoSuchAlgorithmException, InvalidKeyException, InvalidAlgorithmParameterException, NoSuchPaddingException, UnsupportedEncodingException, IllegalBlockSizeException, BadPaddingException {
        byte[] encryptedTextArray = Base64.getDecoder().decode(encryptedText);
        Cipher c = Cipher.getInstance(ALGO_TRANSFORMATION_STRING); // Transformation specifies algortihm, mode of operation and padding
        c.init(Cipher.DECRYPT_MODE, aesKey, gcmParamSpec, new SecureRandom());
        c.updateAAD(aadData); // Add AAD details before decrypting
        byte[] plainTextArray = c.doFinal(encryptedTextArray);
        return new String(plainTextArray);
    }

}

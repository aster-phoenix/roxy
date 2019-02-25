package sd.com.onb.crypto.service;

import java.security.SecureRandom;
import java.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;

/**
 *
 * @author Ghazy
 */
public class AESService {

    private static final String ALGO_TRANSFORMATION_STRING = "AES/GCM/PKCS5Padding";

    public static String encrypt(String message, SecretKey aesKey, GCMParameterSpec gcmParamSpec, byte[] aad) throws Exception {
        Cipher c = null;
        byte[] encryptedTextArray = null;
        c = Cipher.getInstance(ALGO_TRANSFORMATION_STRING); // Transformation specifies algortihm, mode of operation and padding
        c.init(Cipher.ENCRYPT_MODE, aesKey, gcmParamSpec, new SecureRandom());
        c.updateAAD(aad); // add AAD tag data before encrypting
        encryptedTextArray = c.doFinal(message.getBytes("UTF-8"));
        return Base64.getEncoder().encodeToString(encryptedTextArray);
    }

    public static String decrypt(String encryptedText, SecretKey aesKey, GCMParameterSpec gcmParamSpec, byte[] aadData) throws Exception {
        Cipher c = null;
        byte[] encryptedTextArray = Base64.getDecoder().decode(encryptedText);
        byte[] plainTextArray = null;
        c = Cipher.getInstance(ALGO_TRANSFORMATION_STRING); // Transformation specifies algortihm, mode of operation and padding
        c.init(Cipher.DECRYPT_MODE, aesKey, gcmParamSpec, new SecureRandom());
        c.updateAAD(aadData); // Add AAD details before decrypting
        plainTextArray = c.doFinal(encryptedTextArray);
        return new String(plainTextArray);
    }

}

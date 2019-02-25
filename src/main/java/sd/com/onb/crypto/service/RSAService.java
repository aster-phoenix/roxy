package sd.com.onb.crypto.service;

import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.util.Base64;
import javax.crypto.Cipher;

/**
 *
 * @author Ghazy
 */
public class RSAService {

    private static final String ALGO_TRANSFORMATION_STRING = "RSA/ECB/OAEPWITHSHA-512ANDMGF1PADDING";

    public static String encrypt(String message, PublicKey publicKey) throws Exception {
        Cipher c = Cipher.getInstance(ALGO_TRANSFORMATION_STRING);
        c.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] encryptedTextArray = c.doFinal(message.getBytes("UTF-8"));
        return Base64.getEncoder().encodeToString(encryptedTextArray);
    }

    public static String decrypt(String encryptedText, PrivateKey privateKey) throws Exception {
        byte[] encryptedTextArray = Base64.getDecoder().decode(encryptedText);
        Cipher c = Cipher.getInstance(ALGO_TRANSFORMATION_STRING);
        c.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] plainText = c.doFinal(encryptedTextArray);
        return new String(plainText);
    }

    public static String sign(String message,String algorithm, PrivateKey privateKey) throws NoSuchAlgorithmException, InvalidKeyException,
            UnsupportedEncodingException, SignatureException {

        Signature signature = Signature.getInstance(algorithm);
        signature.initSign(privateKey);
        signature.update(message.getBytes("UTF-8"));
        byte[] sign = signature.sign();
        return Base64.getEncoder().encodeToString(sign);
    }

    public static boolean verify(String message, String sign, String algorithm, PublicKey publicKey) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException, UnsupportedEncodingException {
        byte[] signTextArray = Base64.getDecoder().decode(sign);
        Signature signature = Signature.getInstance(algorithm);
        signature.initVerify(publicKey);
        signature.update(message.getBytes("UTF-8"));
        return signature.verify(signTextArray);
    }
}

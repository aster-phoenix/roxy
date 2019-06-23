package xyz.pretsa.roxy.asymmetric;

import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.util.Base64;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

/**
 *
 * @author Ghazy
 */
public class RSACipher {

    private final String ALGO_TRANSFORMATION_STRING = "RSA/ECB/OAEPWITHSHA-512ANDMGF1PADDING";

    protected byte[] encrypt(byte[] message, PublicKey publicKey) throws NoSuchAlgorithmException, InvalidKeyException, UnsupportedEncodingException, IllegalBlockSizeException, BadPaddingException, NoSuchPaddingException {
        Cipher c = Cipher.getInstance(ALGO_TRANSFORMATION_STRING);
        c.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] encryptedTextArray = c.doFinal(message);
        return encryptedTextArray;
    }

    protected byte[] decrypt(byte[] encryptedMessage, PrivateKey privateKey) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        Cipher c = Cipher.getInstance(ALGO_TRANSFORMATION_STRING);
        c.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] message = c.doFinal(encryptedMessage);
        return message;
    }

    protected byte[] sign(byte[] message,String algorithm, PrivateKey privateKey) throws NoSuchAlgorithmException, InvalidKeyException,
            UnsupportedEncodingException, SignatureException {

        Signature signature = Signature.getInstance(algorithm);
        signature.initSign(privateKey);
        signature.update(message);
        byte[] messageSignature = signature.sign();
        return messageSignature;
    }

    protected boolean verify(byte[] message, byte[] messageSignature, String algorithm, PublicKey publicKey) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException, UnsupportedEncodingException {
        Signature signature = Signature.getInstance(algorithm);
        signature.initVerify(publicKey);
        signature.update(message);
        return signature.verify(messageSignature);
    }
}

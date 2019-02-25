package sd.com.onb.crypto;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.nio.file.Path;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import sd.com.onb.crypto.service.AESService;
import sd.com.onb.crypto.service.ConfigService;
import sd.com.onb.crypto.service.KeyService;
import sd.com.onb.crypto.service.MessageDigestService;
import sd.com.onb.crypto.service.RSAService;

/**
 *
 * @author Ghazy
 */
public class CryptoFacade {

    private final String MD5_ALGORITHM = "MD5";
    private final String SHA256_ALGORITHM = "SHA-256";
    private final String SHA512_ALGORITHM = "SHA-512";
    private final String SIGNATURE_ALGORITHM = "SHA512withRSA";

    private KeyService keyService;
    private ConfigService configService;
    public String LAST_ERROR;

    public CryptoFacade() {
    }

    public CryptoFacade(Path workingDirectory) throws IOException {
        keyService = new KeyService(workingDirectory);
        configService = new ConfigService(workingDirectory);
    }

    public void generateAndSaveDefaultKeys() {
        try {
            generateAndSaveCustomKeys("AES", 128, 96, 128, "RSA", 2048);
            configService.saveConfigToFile("AES", 128, 96, 128, "RSA", 2048);
        } catch (IOException ex) {
            LAST_ERROR = ex.getMessage();
        }
    }

    public void generateAndSaveCustomKeys(String symmetricAlgorithm, int symmetricKeySize, int ivSize, int gcmSize,
            String asymmetricAlgorithm, int asymmetricKeySize) {

        try {
            generateAndSaveAesKeys(symmetricAlgorithm, symmetricKeySize, ivSize, gcmSize);
            generateAndSaveRsaKeys(asymmetricAlgorithm, asymmetricKeySize);
            configService.saveConfigToFile(symmetricAlgorithm, symmetricKeySize, ivSize, gcmSize, asymmetricAlgorithm, asymmetricKeySize);
        } catch (IOException ex) {
            LAST_ERROR = ex.getMessage();
        }
    }

    // AES
    private void generateAndSaveAesKeys(String algorithm, int keySize, int ivSize, int gcmSize) {
        try {
            SecretKey secretKey = keyService.generateSecretKey(algorithm, keySize);
            keyService.saveSecreyKey(secretKey, algorithm);
            byte[] aad = keyService.generateAad("random");
            keyService.saveAadKey(aad);
            GCMParameterSpec gcm = keyService.generateGCMParameterSpec(ivSize, gcmSize);
            keyService.saveGcmParamenterSpecKey(gcm);
        } catch (IOException | NoSuchAlgorithmException ex) {
            LAST_ERROR = ex.getMessage();
        }
    }

    public String aesEncrypt(String msg) {
        try {
            SecretKey secretKey = keyService.loadSecretKey(configService.getProperty(configService.SYMMETRIC_ALGO_KEY));
            GCMParameterSpec gcm = keyService.loadGcmParamenterSpecKey(Integer.valueOf(configService.getProperty(configService.GCM_BIT_SIZE_KEY)));
            byte[] aad = keyService.loadAadKey();
            return AESService.encrypt(msg, secretKey, gcm, aad);
        } catch (Exception ex) {
            LAST_ERROR = ex.getMessage();
            return null;
        }
    }

    public String aesEncrypt(String msg, SecretKey secretKey, GCMParameterSpec gcm, byte[] aad) {
        try {
            return AESService.encrypt(msg, secretKey, gcm, aad);
        } catch (Exception ex) {
            LAST_ERROR = ex.getMessage();
            return null;
        }
    }

    public String aesDecrypt(String encryptedMsg) {
        try {
            SecretKey secretKey = keyService.loadSecretKey(configService.getProperty(configService.SYMMETRIC_ALGO_KEY));
            GCMParameterSpec gcm = keyService.loadGcmParamenterSpecKey(Integer.valueOf(configService.getProperty(configService.GCM_BIT_SIZE_KEY)));
            byte[] aad = keyService.loadAadKey();
            return AESService.decrypt(encryptedMsg, secretKey, gcm, aad);
        } catch (Exception ex) {
            LAST_ERROR = ex.getMessage();
            ex.printStackTrace();
            return null;
        }
    }

    public String aesDecrypt(String encryptedMsg, SecretKey secretKey, GCMParameterSpec gcm, byte[] aad) {
        try {
            return AESService.decrypt(encryptedMsg, secretKey, gcm, aad);
        } catch (Exception ex) {
            LAST_ERROR = ex.getMessage();
            return null;
        }
    }

    // RSA
    private void generateAndSaveRsaKeys(String algorithm, int keySize) {
        try {
            KeyPair keyPair = keyService.generateKeyPair(algorithm, keySize);
            keyService.saveKeyPair(keyPair);
        } catch (IOException | NoSuchAlgorithmException ex) {
            LAST_ERROR = ex.getMessage();
        }
    }

    public String rsaEncrypt(String msg) {
        try {
            KeyPair keyPair = keyService.loadKeyPair(configService.getProperty(configService.ASYMMETRIC_ALGO_KEY));
            return RSAService.encrypt(msg, keyPair.getPublic());
        } catch (Exception ex) {
            LAST_ERROR = ex.getMessage();
            return null;
        }
    }

    public String rsaDecrypt(String encryptedMsg) {
        try {
            KeyPair keyPair = keyService.loadKeyPair(configService.getProperty(configService.ASYMMETRIC_ALGO_KEY));
            return RSAService.decrypt(encryptedMsg, keyPair.getPrivate());
        } catch (Exception ex) {
            LAST_ERROR = ex.getMessage();
            return null;
        }
    }

    public String rsaSignWithSHA512(String msg) {
        return rsaSign(msg, SIGNATURE_ALGORITHM);
    }

    public String rsaSign(String msg, String algorithm) {
        try {
            KeyPair keyPair = keyService.loadKeyPair(configService.getProperty(configService.ASYMMETRIC_ALGO_KEY));
            return RSAService.sign(msg, algorithm, keyPair.getPrivate());
        } catch (IOException | InvalidKeyException | NoSuchAlgorithmException | SignatureException | InvalidKeySpecException ex) {
            LAST_ERROR = ex.getMessage();
            return null;
        }
    }

    public boolean rsaVerifyWithSHA512(String msg, String signature) {
        return rsaVerify(msg, signature, SIGNATURE_ALGORITHM);
    }

    public boolean rsaVerify(String msg, String signature, String algorithm) {
        try {
            KeyPair keyPair = keyService.loadKeyPair(configService.getProperty(configService.ASYMMETRIC_ALGO_KEY));
            return RSAService.verify(msg, signature, algorithm, keyPair.getPublic());
        } catch (IOException | InvalidKeyException | NoSuchAlgorithmException | SignatureException | InvalidKeySpecException ex) {
            LAST_ERROR = ex.getMessage();
            return false;
        }
    }

    // Message Disgest
    public byte[] hashWithMd5(String msg) {
        return hash(msg, MD5_ALGORITHM);
    }

    public byte[] hashWithSha256(String msg) {
        return hash(msg, SHA256_ALGORITHM);
    }

    public byte[] hashWithSha512(String msg) {
        return hash(msg, SHA512_ALGORITHM);
    }

    public byte[] hash(String msg, String algorithm) {
        try {
            return MessageDigestService.hash(msg, algorithm);
        } catch (NoSuchAlgorithmException | UnsupportedEncodingException ex) {
            LAST_ERROR = ex.getMessage();
            ex.printStackTrace();
            return null;
        }
    }

}

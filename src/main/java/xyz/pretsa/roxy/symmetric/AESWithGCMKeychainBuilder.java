package xyz.pretsa.roxy.symmetric;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Path;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 *
 * @author ghazy
 */
public class AESWithGCMKeychainBuilder {

    private static final String ALGO = "AES";
    private static final int KEY_SIZE = 128;
    private static final int IV_SIZE = 96;
    private static final int GCM_SIZE = 128;
    private static final String FIXED_AAD = "ROXY_AAD";

    public static AESWithGCMKeychain newMinimalKeychain() throws NoSuchAlgorithmException {
        return new AESWithGCMKeychain(generateSecretKey(KEY_SIZE), generateGCMParameterSpec(IV_SIZE, GCM_SIZE), generateAad(FIXED_AAD));
    }
    
    public static AESWithGCMKeychain withExistingSecretKey(SecretKey secretKey) throws NoSuchAlgorithmException {
        return new AESWithGCMKeychain(secretKey, generateGCMParameterSpec(IV_SIZE, GCM_SIZE), generateAad(FIXED_AAD));
    }
    
    public static AESWithGCMKeychain withExistingKeys(SecretKey secretKey, GCMParameterSpec gcm, byte[] aad) throws NoSuchAlgorithmException {
        return new AESWithGCMKeychain(secretKey, gcm, aad);
    }
    
    public static AESWithGCMKeychain withExistingKeys(byte[] encodedSecretKey, int gcmSize, byte[] encodedGcm, byte[] aad) throws NoSuchAlgorithmException {
        SecretKey secretKey = getSecretKeyFromEncodedKey(encodedSecretKey);
        GCMParameterSpec gcm = getGcmParameterSpecFromEncodedIv(gcmSize, encodedGcm);
        return new AESWithGCMKeychain(secretKey, gcm, aad);
    }
    
    public static AESWithGCMKeychain withExistingKeys(String base64EncodedSecretKey, int gcmSize, String base64EncodedGcm, String base64EncodedAad) throws NoSuchAlgorithmException {
        byte[] encodedSecretKey = Base64.getDecoder().decode(base64EncodedSecretKey);
        byte[] encodedGcm = Base64.getDecoder().decode(base64EncodedGcm);
        byte[] aad = Base64.getDecoder().decode(base64EncodedAad);
        SecretKey secretKey = getSecretKeyFromEncodedKey(encodedSecretKey);
        GCMParameterSpec gcm = getGcmParameterSpecFromEncodedIv(gcmSize, encodedGcm);
        return new AESWithGCMKeychain(secretKey, gcm, aad);
    }
    
    public static AESWithGCMKeychain withNewKeysAtPath(Path keysPath) throws NoSuchAlgorithmException, IOException, InvalidKeySpecException {
        saveSecreyKeyToPath(generateSecretKey(KEY_SIZE), keysPath);
        saveGcmParameterSpecToPath(generateGCMParameterSpec(IV_SIZE, GCM_SIZE), keysPath);
        saveAadToPath(generateAad(FIXED_AAD), keysPath);
        return new AESWithGCMKeychain(loadSecretKeyFromPath(keysPath), loadGcmParamenterSpecFromPath(GCM_SIZE, keysPath), loadAadFromPath(keysPath));
    }
    
    public static AESWithGCMKeychain withExistingKeysAtPath(Path keysPath) throws NoSuchAlgorithmException, IOException, InvalidKeySpecException {
        return new AESWithGCMKeychain(loadSecretKeyFromPath(keysPath), loadGcmParamenterSpecFromPath(GCM_SIZE, keysPath), loadAadFromPath(keysPath));
    }

    public static SecretKey generateSecretKey(int keySize) throws NoSuchAlgorithmException {
        KeyGenerator keygen = KeyGenerator.getInstance(ALGO); // Specifying algorithm key will be used for 
        keygen.init(keySize); // Specifying Key size to be used, Note: This would need JCE Unlimited Strength to be installed explicitly 
        SecretKey secretKey = keygen.generateKey();
        return secretKey;
    }

    public static GCMParameterSpec generateGCMParameterSpec(int ivSize, int gcmSize) {
        // Generating IV
        byte iv[] = new byte[ivSize];
        SecureRandom secRandom = new SecureRandom();
        secRandom.nextBytes(iv); // SecureRandom initialized using self-seeding

        // Initialize GCM Parameters
        GCMParameterSpec gcmParamSpec = new GCMParameterSpec(gcmSize, iv);
        return gcmParamSpec;
    }

    public static byte[] generateAad(String aad) {
        return aad.getBytes();
    }

    

    public static SecretKey loadSecretKeyFromPath(Path secretKeyPath) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        // Read Secret Key.
        File fileSecretKey = secretKeyPath.resolve("secret.key").toFile();
        byte[] encodedSecretKey;
        try (FileInputStream fis = new FileInputStream(fileSecretKey)) {
            encodedSecretKey = new byte[(int) fileSecretKey.length()];
            fis.read(encodedSecretKey);
        }
        // Generate Secret key.
        return getSecretKeyFromEncodedKey(encodedSecretKey);
    }

    public static GCMParameterSpec loadGcmParamenterSpecFromPath(int gcmSize, Path gcmPath) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        // Read Secret Key.
        File fileGcmKey = gcmPath.resolve("gcm.key").toFile();
        byte[] iv;
        try (FileInputStream fis = new FileInputStream(fileGcmKey)) {
            iv = new byte[(int) fileGcmKey.length()];
            fis.read(iv);
        }
        // Generate GCM Parameter Spec key.
        return getGcmParameterSpecFromEncodedIv(gcmSize, iv);
    }

    public static byte[] loadAadFromPath(Path aadPath) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        // Read Aad Key.
        File fileAadKey = aadPath.resolve("aad.key").toFile();
        byte[] aad;
        try (FileInputStream fis = new FileInputStream(fileAadKey)) {
            aad = new byte[(int) fileAadKey.length()];
            fis.read(aad);
        }
        return aad;
    }
    public static void saveSecreyKeyToPath(SecretKey key, Path secretKeyPath) throws IOException {
        // Store Public Key.
        SecretKeySpec spec = new SecretKeySpec(key.getEncoded(), ALGO);
        try (FileOutputStream fos = new FileOutputStream(secretKeyPath.resolve("secret.key").toFile())) {
            fos.write(spec.getEncoded());
        }
    }

    public static void saveGcmParameterSpecToPath(GCMParameterSpec spec, Path gcmPath) throws IOException {
        // Store GCM parameter spec Key.
        try (FileOutputStream fos = new FileOutputStream(gcmPath.resolve("gcm.key").toFile())) {
            fos.write(spec.getIV());
        }
    }

    public static void saveAadToPath(byte[] aad, Path aadPath) throws IOException {
        // Store AAD Key.
        try (FileOutputStream fos = new FileOutputStream(aadPath.resolve("aad.key").toFile())) {
            fos.write(aad);
        }
    }
    
    private static SecretKey getSecretKeyFromEncodedKey(byte[] encodedSecretKey) {
        SecretKeySpec spec = new SecretKeySpec(encodedSecretKey, ALGO);
        SecretKey secretKey = spec;
        return secretKey;
    }
    
    private static GCMParameterSpec getGcmParameterSpecFromEncodedIv(int gcmSize, byte[] iv) {
        GCMParameterSpec spec = new GCMParameterSpec(gcmSize, iv);
        return spec;
    }
}

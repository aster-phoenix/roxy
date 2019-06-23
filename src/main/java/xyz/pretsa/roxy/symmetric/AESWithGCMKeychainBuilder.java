package xyz.pretsa.roxy.symmetric;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Path;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import xyz.pretsa.roxy.converter.Converters;

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

    public static AESWithGCMKeychain withNewKeychain() throws NoSuchAlgorithmException {
        return new AESWithGCMKeychain(generateSecretKey(KEY_SIZE), generateGCMParameterSpec(IV_SIZE, GCM_SIZE), generateAad(FIXED_AAD));
    }

    public static AESWithGCMKeychain withExistingSecretKey(SecretKey secretKey) throws NoSuchAlgorithmException {
        return new AESWithGCMKeychain(secretKey, generateGCMParameterSpec(IV_SIZE, GCM_SIZE), generateAad(FIXED_AAD));
    }

    public static AESWithGCMKeychain withExistingKeys(SecretKey secretKey, GCMParameterSpec gcm, byte[] aad) throws NoSuchAlgorithmException {
        return new AESWithGCMKeychain(secretKey, gcm, aad);
    }

    public static AESWithGCMKeychain withExistingEncodedKeys(byte[] encodedSecretKey, int gcmSize, byte[] encodedGcm, byte[] aad) throws NoSuchAlgorithmException {
        SecretKey secretKey = getSecretKeyFromEncodedKey(encodedSecretKey);
        GCMParameterSpec gcm = getGcmParameterSpecFromEncodedIv(gcmSize, encodedGcm);
        return new AESWithGCMKeychain(secretKey, gcm, aad);
    }

    public static AESWithGCMKeychain withExistingEncodedKeys(String encodedSecretKeyString, int gcmSize, String encodedGcmString, String encodedAadString) throws NoSuchAlgorithmException {
        SecretKey secretKey = getSecretKeyFromEncodedKey(encodedSecretKeyString);
        GCMParameterSpec gcm = getGcmParameterSpecFromEncodedIv(gcmSize, encodedGcmString);
        byte[] aad = getAadfromEncodedString(encodedAadString);
        return new AESWithGCMKeychain(secretKey, gcm, aad);
    }

    public static AESWithGCMKeychain withNewKeysAtPath(Path keysPath) throws NoSuchAlgorithmException, IOException, InvalidKeySpecException {
        AESWithGCMKeychain keychain = withNewKeychain();
        saveKeycainToPath(keychain, keysPath);
        return keychain;
    }

    public static AESWithGCMKeychain withExistingKeysAtPath(Path keysPath) throws NoSuchAlgorithmException, IOException, InvalidKeySpecException {
        return loadKeychainFromPath(GCM_SIZE, keysPath);
    }

    private static SecretKey generateSecretKey(int keySize) throws NoSuchAlgorithmException {
        KeyGenerator keygen = KeyGenerator.getInstance(ALGO); // Specifying algorithm key will be used for 
        keygen.init(keySize); // Specifying Key size to be used, Note: This would need JCE Unlimited Strength to be installed explicitly 
        SecretKey secretKey = keygen.generateKey();
        return secretKey;
    }

    private static GCMParameterSpec generateGCMParameterSpec(int ivSize, int gcmSize) {
        // Generating IV
        byte iv[] = new byte[ivSize];
        SecureRandom secRandom = new SecureRandom();
        secRandom.nextBytes(iv); // SecureRandom initialized using self-seeding

        // Initialize GCM Parameters
        GCMParameterSpec gcmParamSpec = new GCMParameterSpec(gcmSize, iv);
        return gcmParamSpec;
    }

    private static byte[] generateAad(String aad) {
        return aad.getBytes();
    }

    private static AESWithGCMKeychain loadKeychainFromPath(int gcmSize, Path keychainPath) throws IOException {
        // Read Secret Key.
        File fileSecretKey = keychainPath.resolve("secret.key").toFile();
        byte[] encodedSecretKey;
        FileInputStream fis = new FileInputStream(fileSecretKey);
        encodedSecretKey = new byte[(int) fileSecretKey.length()];
        fis.read(encodedSecretKey);
        fis.close();
        // Generate Secret key.
        SecretKey secretKey = getSecretKeyFromEncodedKey(encodedSecretKey);

        // Read Secret Key.
        File fileGcmKey = keychainPath.resolve("gcm.key").toFile();
        byte[] iv;
        fis = new FileInputStream(fileGcmKey);
        iv = new byte[(int) fileGcmKey.length()];
        fis.read(iv);
        fis.close();
        // Generate GCM Parameter Spec key.
        GCMParameterSpec gcm = getGcmParameterSpecFromEncodedIv(gcmSize, iv);

        // Read Aad Key.
        File fileAadKey = keychainPath.resolve("aad.key").toFile();
        byte[] aad;
        fis = new FileInputStream(fileAadKey);
        aad = new byte[(int) fileAadKey.length()];
        fis.read(aad);
        fis.close();

        return new AESWithGCMKeychain(secretKey, gcm, aad);

    }

    private static void saveKeycainToPath(AESWithGCMKeychain keychain, Path keychainPath) throws FileNotFoundException, IOException {
        // Store Public Key.
        SecretKeySpec spec = new SecretKeySpec(keychain.getEncodedSecretKey(), ALGO);
        FileOutputStream fos = new FileOutputStream(keychainPath.resolve("secret.key").toFile());
        fos.write(spec.getEncoded());
        fos.close();

        // Store GCM parameter spec Key.
        fos = new FileOutputStream(keychainPath.resolve("gcm.key").toFile());
        fos.write(keychain.getEncodedGcm());
        fos.close();

        // Store AAD Key.
        fos = new FileOutputStream(keychainPath.resolve("aad.key").toFile());
        fos.write(keychain.getAad());
        fos.close();

    }

    private static SecretKey getSecretKeyFromEncodedKey(String encodedSecretKeyString) {
        return getSecretKeyFromEncodedKey(Converters.base64ToBytes(encodedSecretKeyString));
    }

    private static SecretKey getSecretKeyFromEncodedKey(byte[] encodedSecretKey) {
        SecretKeySpec spec = new SecretKeySpec(encodedSecretKey, ALGO);
        SecretKey secretKey = spec;
        return secretKey;
    }

    private static GCMParameterSpec getGcmParameterSpecFromEncodedIv(int gcmSize, String ivString) {
        byte[] iv = Converters.base64ToBytes(ivString);
        return getGcmParameterSpecFromEncodedIv(gcmSize, iv);
    }

    private static GCMParameterSpec getGcmParameterSpecFromEncodedIv(int gcmSize, byte[] iv) {
        GCMParameterSpec spec = new GCMParameterSpec(gcmSize, iv);
        return spec;
    }

    private static byte[] getAadfromEncodedString(String AadString) {
        return Converters.base64ToBytes(AadString);
    }
}

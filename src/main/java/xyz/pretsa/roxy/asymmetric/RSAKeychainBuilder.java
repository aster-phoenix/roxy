package xyz.pretsa.roxy.asymmetric;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.nio.file.Path;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import xyz.pretsa.roxy.converter.Converters;

/**
 *
 * @author ghazy
 */
public class RSAKeychainBuilder {
    
    private static final String ALGO = "RSA";
    private static final int KEY_SIZE = 2048;
    private static final String UTF_8 = "UTF-8";
    
    public static RSAKeychain withNewKeychain() throws NoSuchAlgorithmException {        
        return new RSAKeychain(generateKeyPair(KEY_SIZE));
    }
    
    public static RSAKeychain withNewKeychain(int keySize) throws NoSuchAlgorithmException {        
        return new RSAKeychain(generateKeyPair(keySize));
    }
    
    public static RSAKeychain withExistingKeyPair(KeyPair keyPair) throws NoSuchAlgorithmException {        
        return new RSAKeychain(keyPair);
    }
    
    public static RSAKeychain withExistingKeys(PublicKey publicKey, PrivateKey privateKey) throws NoSuchAlgorithmException {        
        return new RSAKeychain(publicKey, privateKey);
    }
    
    public static RSAKeychain withExistingEncodedKeys(byte[] encodedPublicKey, byte[] encodedPrivateKey) throws NoSuchAlgorithmException, UnsupportedEncodingException, InvalidKeySpecException {        
        PublicKey publicKey = getPublicKeyFromEncodedKey(encodedPublicKey);
        PrivateKey privateKey = getPrivateKeyFromEncodedKey(encodedPrivateKey);
        return new RSAKeychain(publicKey, privateKey);
    }
    
    public static RSAKeychain withExistingEncodedKeys(String encodedPublicKeyString, String encodedPrivateKeyString) throws NoSuchAlgorithmException, UnsupportedEncodingException, InvalidKeySpecException {        
        PublicKey publicKey = getPublicKeyFromEncodedKey(encodedPublicKeyString);
        PrivateKey privateKey = getPrivateKeyFromEncodedKey(encodedPrivateKeyString);
        return new RSAKeychain(publicKey, privateKey);
    }
    public static RSAKeychain withExistingEncodedPublicKey(String encodedPublicKeyString) throws NoSuchAlgorithmException, UnsupportedEncodingException, InvalidKeySpecException {        
        PublicKey publicKey = getPublicKeyFromEncodedKey(encodedPublicKeyString);
        return new RSAKeychain(publicKey, null);
    }
    public static RSAKeychain withExistingEncodedPrivateKey(String encodedPrivateKeyString) throws NoSuchAlgorithmException, UnsupportedEncodingException, InvalidKeySpecException {        
        PrivateKey privateKey = getPrivateKeyFromEncodedKey(encodedPrivateKeyString);
        return new RSAKeychain(null, privateKey);
    }
    
    public static RSAKeychain withExistingKeyPairAtPath(Path keyPairPath) throws NoSuchAlgorithmException, IOException, InvalidKeySpecException {        
        return loadKeychainFromPath(keyPairPath);
    }
    
    public static RSAKeychain withNewKeychainAtPath(Path keyPairPath) throws NoSuchAlgorithmException, IOException, InvalidKeySpecException {        
        RSAKeychain keychain = RSAKeychainBuilder.withNewKeychain();
        saveKeychainToPath(keychain, keyPairPath);
        return keychain;
    }
    
    public static RSAKeychain withNewKeychainAtPath(int keySize, Path keyPairPath) throws NoSuchAlgorithmException, IOException, InvalidKeySpecException {        
        RSAKeychain keychain = withNewKeychain(keySize);
        saveKeychainToPath(keychain, keyPairPath);
        return keychain;
    }
    
    private static KeyPair generateKeyPair(int keySize) throws NoSuchAlgorithmException {
        KeyPairGenerator rsaKeyGen = KeyPairGenerator.getInstance(ALGO);
        rsaKeyGen.initialize(keySize);
        return rsaKeyGen.generateKeyPair();
    }
    
    private static RSAKeychain loadKeychainFromPath(Path keyPairPath) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        // Read Public Key.
        File filePublicKey = keyPairPath.resolve("public.key").toFile();
        FileInputStream fis = new FileInputStream(keyPairPath.resolve("public.key").toFile());
        byte[] encodedPublicKey = new byte[(int) filePublicKey.length()];
        fis.read(encodedPublicKey);
        fis.close();

        // Read Private Key.
        File filePrivateKey = keyPairPath.resolve("private.key").toFile();
        fis = new FileInputStream(keyPairPath.resolve("private.key").toFile());
        byte[] encodedPrivateKey = new byte[(int) filePrivateKey.length()];
        fis.read(encodedPrivateKey);
        fis.close();

        // Generate KeyPair.
        PublicKey publicKey = getPublicKeyFromEncodedKey(encodedPublicKey);
        PrivateKey privateKey = getPrivateKeyFromEncodedKey(encodedPrivateKey);

        return new RSAKeychain(publicKey, privateKey);
    }
    
    private static void saveKeychainToPath(RSAKeychain keychain, Path keyPairPath) throws IOException {

        // Store Public Key.
        FileOutputStream fos = new FileOutputStream(keyPairPath.resolve("public.key").toFile());
        fos.write(keychain.getEncodedPublicKey());
        fos.close();

        // Store Private Key.
        fos = new FileOutputStream(keyPairPath.resolve("private.key").toFile());
        fos.write(keychain.getEncodedPrivateKey());
        fos.close();
    }
    
    private static PublicKey getPublicKeyFromEncodedKey(String encodedPublicKeyString) throws NoSuchAlgorithmException, InvalidKeySpecException {
        return getPublicKeyFromEncodedKey(Converters.base64ToBytes(encodedPublicKeyString));
    }
    private static PublicKey getPublicKeyFromEncodedKey(byte[] encodedPublicKey) throws NoSuchAlgorithmException, InvalidKeySpecException {
        KeyFactory keyFactory = KeyFactory.getInstance(ALGO);
        X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(encodedPublicKey);
        return keyFactory.generatePublic(publicKeySpec);
    }
    
    private static PrivateKey getPrivateKeyFromEncodedKey(String encodedPrivateKeyString) throws NoSuchAlgorithmException, InvalidKeySpecException {
        return getPrivateKeyFromEncodedKey(Converters.base64ToBytes(encodedPrivateKeyString));
    }
    private static PrivateKey getPrivateKeyFromEncodedKey(byte[] encodedPrivateKey) throws NoSuchAlgorithmException, InvalidKeySpecException {
        KeyFactory keyFactory = KeyFactory.getInstance(ALGO);
        PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(encodedPrivateKey);
        return keyFactory.generatePrivate(privateKeySpec);
    }
    
}

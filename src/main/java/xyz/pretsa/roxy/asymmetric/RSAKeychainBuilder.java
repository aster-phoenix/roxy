package xyz.pretsa.roxy.asymmetric;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.nio.charset.Charset;
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
import java.util.Base64;

/**
 *
 * @author ghazy
 */
public class RSAKeychainBuilder {
    
    private static final String ALGO = "RSA";
    private static final int KEY_SIZE = 2048;
    private static final String UTF_8 = "UTF-8";
    
    public static RSAKeychain withNewKeyPair() throws NoSuchAlgorithmException {        
        return new RSAKeychain(generateKeyPair(KEY_SIZE));
    }
    
    public static RSAKeychain withNewKeyPair(int keySize) throws NoSuchAlgorithmException {        
        return new RSAKeychain(generateKeyPair(keySize));
    }
    
    public static RSAKeychain withExistingKeyPair(KeyPair keyPair) throws NoSuchAlgorithmException {        
        return new RSAKeychain(keyPair);
    }
    
    public static RSAKeychain withExistingKeys(PublicKey publicKey, PrivateKey privateKey) throws NoSuchAlgorithmException {        
        return new RSAKeychain(publicKey, privateKey);
    }
    
    public static RSAKeychain withExistingKeys(byte[] encodedPublicKey, byte[] encodedPrivateKey) throws NoSuchAlgorithmException, UnsupportedEncodingException, InvalidKeySpecException {        
        PublicKey publicKey = getPublicKeyFromEncodedKey(encodedPublicKey);
        PrivateKey privateKey = getPrivateKeyFromEncodedKey(encodedPrivateKey);
        return new RSAKeychain(publicKey, privateKey);
    }
    
    public static RSAKeychain withExistingKeys(String base64EncodedPublicKey, String base64EncodedPrivateKey) throws NoSuchAlgorithmException, UnsupportedEncodingException, InvalidKeySpecException {        
        byte[] encodedPublicKey = Base64.getDecoder().decode(base64EncodedPublicKey);
        byte[] encodedPrivateKey = Base64.getDecoder().decode(base64EncodedPrivateKey);
        PublicKey publicKey = getPublicKeyFromEncodedKey(encodedPublicKey);
        PrivateKey privateKey = getPrivateKeyFromEncodedKey(encodedPrivateKey);
        return new RSAKeychain(publicKey, privateKey);
    }
    
    public static RSAKeychain withExistingKeyPairAtPath(Path keyPairPath) throws NoSuchAlgorithmException, IOException, InvalidKeySpecException {        
        return new RSAKeychain(loadKeyPairFromPath(keyPairPath));
    }
    
    public static RSAKeychain withNewKeyPairAtPath(Path keyPairPath) throws NoSuchAlgorithmException, IOException, InvalidKeySpecException {        
        saveKeyPairToPath(generateKeyPair(KEY_SIZE), keyPairPath);
        return new RSAKeychain(loadKeyPairFromPath(keyPairPath));
    }
    
    public static RSAKeychain withNewKeyPairAtPath(int keySize, Path keyPairPath) throws NoSuchAlgorithmException, IOException, InvalidKeySpecException {        
        saveKeyPairToPath(generateKeyPair(keySize), keyPairPath);
        return new RSAKeychain(loadKeyPairFromPath(keyPairPath));
    }
    
    private static KeyPair generateKeyPair(int keySize) throws NoSuchAlgorithmException {
        KeyPairGenerator rsaKeyGen = KeyPairGenerator.getInstance(ALGO);
        rsaKeyGen.initialize(keySize);
        return rsaKeyGen.generateKeyPair();
    }
    
    private static KeyPair loadKeyPairFromPath(Path keyPairPath) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
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

        return new KeyPair(publicKey, privateKey);
    }
    
    private static void saveKeyPairToPath(KeyPair keyPair, Path keyPairPath) throws IOException {
        PrivateKey privateKey = keyPair.getPrivate();
        PublicKey publicKey = keyPair.getPublic();

        // Store Public Key.
        FileOutputStream fos = new FileOutputStream(keyPairPath.resolve("public.key").toFile());
        fos.write(encodePublicKey(publicKey));
        fos.close();

        // Store Private Key.
        fos = new FileOutputStream(keyPairPath.resolve("private.key").toFile());
        fos.write(encodePrivateKey(privateKey));
        fos.close();
    }
    
    private static PublicKey getPublicKeyFromEncodedKey(byte[] encodedPublicKey) throws NoSuchAlgorithmException, InvalidKeySpecException {
        KeyFactory keyFactory = KeyFactory.getInstance(ALGO);
        X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(encodedPublicKey);
        return keyFactory.generatePublic(publicKeySpec);
    }
    
    private static PrivateKey getPrivateKeyFromEncodedKey(byte[] encodedPrivateKey) throws NoSuchAlgorithmException, InvalidKeySpecException {
        KeyFactory keyFactory = KeyFactory.getInstance(ALGO);
        PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(encodedPrivateKey);
        return keyFactory.generatePrivate(privateKeySpec);
    }
    
    public static byte[] encodePublicKey(PublicKey publicKey) {
        X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(publicKey.getEncoded());
        return x509EncodedKeySpec.getEncoded();
    }
    
    public static byte[] encodePrivateKey(PrivateKey privateKey) {
        PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(privateKey.getEncoded());
        return pkcs8EncodedKeySpec.getEncoded();
    }
}

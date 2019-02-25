package xyz.pretsa.roxy.asymmetric;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
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

/**
 *
 * @author ghazy
 */
public class RSAKeychainBuilder {
    
    private static final String ALGO = "RSA";
    private static final int KEY_SIZE = 2048;
    
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
        KeyFactory keyFactory = KeyFactory.getInstance(ALGO);
        X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(encodedPublicKey);
        PublicKey publicKey = keyFactory.generatePublic(publicKeySpec);

        PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(encodedPrivateKey);
        PrivateKey privateKey = keyFactory.generatePrivate(privateKeySpec);

        return new KeyPair(publicKey, privateKey);
    }
    
    private static void saveKeyPairToPath(KeyPair keyPair, Path keyPairPath) throws IOException {
        PrivateKey privateKey = keyPair.getPrivate();
        PublicKey publicKey = keyPair.getPublic();

        // Store Public Key.
        X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(publicKey.getEncoded());
        FileOutputStream fos = new FileOutputStream(keyPairPath.resolve("public.key").toFile());
        fos.write(x509EncodedKeySpec.getEncoded());
        fos.close();

        // Store Private Key.
        PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(privateKey.getEncoded());
        fos = new FileOutputStream(keyPairPath.resolve("private.key").toFile());
        fos.write(pkcs8EncodedKeySpec.getEncoded());
        fos.close();
    }
    
}

package sd.com.onb.crypto.service;

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
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 *
 * @author Ghazy
 */
public class KeyService {
    
    private Path workingDirectory;

    public KeyService() {
    }

    public KeyService(Path workingDirectory) {
        this.workingDirectory = workingDirectory;
    }

    // Secret Key
    public SecretKey generateSecretKey(String algorithm, int keySize) throws NoSuchAlgorithmException {
        KeyGenerator keygen = KeyGenerator.getInstance(algorithm); // Specifying algorithm key will be used for 
        keygen.init(keySize); // Specifying Key size to be used, Note: This would need JCE Unlimited Strength to be installed explicitly 
        SecretKey secretKey = keygen.generateKey();
        return secretKey;
    }
    
    public byte[] generateAad(String aad) {
        return aad.getBytes();
    }
    
    public GCMParameterSpec generateGCMParameterSpec(int ivSize, int gcmBitSize) {
        // Generating IV
        byte iv[] = new byte[ivSize];
        SecureRandom secRandom = new SecureRandom();
        secRandom.nextBytes(iv); // SecureRandom initialized using self-seeding

        // Initialize GCM Parameters
        GCMParameterSpec gcmParamSpec = new GCMParameterSpec(gcmBitSize, iv);
        return gcmParamSpec;
    }
    
    public void saveAadKey(byte[] aad) throws IOException {
        // Store AAD Key.
        try (FileOutputStream fos = new FileOutputStream(workingDirectory.resolve("aad.key").toFile())) {
            fos.write(aad);
        }
    }
    
    public void saveGcmParamenterSpecKey(GCMParameterSpec spec) throws IOException {
        // Store GCM parameter spec Key.
        try (FileOutputStream fos = new FileOutputStream(workingDirectory.resolve("gcm.key").toFile())) {
            fos.write(spec.getIV());
        }
    }

    public void saveSecreyKey(SecretKey key, String algorithm) throws IOException {
        // Store Public Key.
        SecretKeySpec spec = new SecretKeySpec(key.getEncoded(), algorithm);
        try (FileOutputStream fos = new FileOutputStream(workingDirectory.resolve("secret.key").toFile())) {
            fos.write(spec.getEncoded());
        }
    }
    
    public byte[] loadAadKey() throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        // Read Aad Key.
        File fileAadKey = workingDirectory.resolve("aad.key").toFile();
        byte[] aad;
        try (FileInputStream fis = new FileInputStream(fileAadKey)) {
            aad = new byte[(int) fileAadKey.length()];
            fis.read(aad);
        }
        return aad;
    }
    
    public GCMParameterSpec loadGcmParamenterSpecKey(int tagSize) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        // Read Secret Key.
        File fileGcmKey = workingDirectory.resolve("gcm.key").toFile();
        byte[] iv;
        try (FileInputStream fis = new FileInputStream(fileGcmKey)) {
            iv = new byte[(int) fileGcmKey.length()];
            fis.read(iv);
        }
        // Generate GCM Parameter Spec key.
        GCMParameterSpec spec = new GCMParameterSpec(tagSize, iv);
        return spec;
    }

    public SecretKey loadSecretKey(String algorithm) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        // Read Secret Key.
        File fileSecretKey = workingDirectory.resolve("secret.key").toFile();
        byte[] encodedSecretKey;
        try (FileInputStream fis = new FileInputStream(fileSecretKey)) {
            encodedSecretKey = new byte[(int) fileSecretKey.length()];
            fis.read(encodedSecretKey);
        }
        // Generate Secret key.
        SecretKeySpec spec = new SecretKeySpec(encodedSecretKey, algorithm);
        SecretKey secretKey = spec;
        return secretKey;
    }

    // KeyPair
    public KeyPair generateKeyPair(String algorithm, int keySize) throws NoSuchAlgorithmException {
        KeyPairGenerator rsaKeyGen = KeyPairGenerator.getInstance(algorithm);
        rsaKeyGen.initialize(keySize);
        KeyPair rsaKeyPair = rsaKeyGen.generateKeyPair();
        return rsaKeyPair;
    }

    public void saveKeyPair(KeyPair keyPair) throws IOException {
        PrivateKey privateKey = keyPair.getPrivate();
        PublicKey publicKey = keyPair.getPublic();

        // Store Public Key.
        X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(publicKey.getEncoded());
        FileOutputStream fos = new FileOutputStream(workingDirectory.resolve("public.key").toFile());
        fos.write(x509EncodedKeySpec.getEncoded());
        fos.close();

        // Store Private Key.
        PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(privateKey.getEncoded());
        fos = new FileOutputStream(workingDirectory.resolve("private.key").toFile());
        fos.write(pkcs8EncodedKeySpec.getEncoded());
        fos.close();
    }

    public KeyPair loadKeyPair(String algorithm) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        // Read Public Key.
        File filePublicKey = workingDirectory.resolve("public.key").toFile();
        FileInputStream fis = new FileInputStream(workingDirectory.resolve("public.key").toFile());
        byte[] encodedPublicKey = new byte[(int) filePublicKey.length()];
        fis.read(encodedPublicKey);
        fis.close();

        // Read Private Key.
        File filePrivateKey = workingDirectory.resolve("private.key").toFile();
        fis = new FileInputStream(workingDirectory.resolve("private.key").toFile());
        byte[] encodedPrivateKey = new byte[(int) filePrivateKey.length()];
        fis.read(encodedPrivateKey);
        fis.close();

        // Generate KeyPair.
        KeyFactory keyFactory = KeyFactory.getInstance(algorithm);
        X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(encodedPublicKey);
        PublicKey publicKey = keyFactory.generatePublic(publicKeySpec);

        PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(encodedPrivateKey);
        PrivateKey privateKey = keyFactory.generatePrivate(privateKeySpec);

        return new KeyPair(publicKey, privateKey);
    }
}
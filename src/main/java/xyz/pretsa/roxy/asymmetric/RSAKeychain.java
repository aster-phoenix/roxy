package xyz.pretsa.roxy.asymmetric;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import xyz.pretsa.roxy.converter.Converters;

/**
 *
 * @author ghazy
 */
public class RSAKeychain {
    
    private KeyPair keyPair;
    private PublicKey publicKey;
    private PrivateKey privateKey;
    

    public RSAKeychain(KeyPair keyPair) {
        this.keyPair = keyPair;
        this.publicKey = keyPair.getPublic();
        this.privateKey = keyPair.getPrivate();
    }

    public RSAKeychain(PublicKey publicKey, PrivateKey privateKey) {
        keyPair = new KeyPair(publicKey, privateKey);
        this.publicKey = publicKey;
        this.privateKey = privateKey;
    }

    public KeyPair getKeyPair() {
        return keyPair;
    }

    public void setKeyPair(KeyPair keyPair) {
        this.keyPair = keyPair;
    }

    public PublicKey getPublicKey() {
        return publicKey;
    }
    
    public byte[] getEncodedPublicKey() {
        X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(publicKey.getEncoded());
        return x509EncodedKeySpec.getEncoded();
    }
    
    public String getEncodedPublicKeyAsString() {
        return Converters.bytesToBase64(getEncodedPublicKey());
    }

    public void setPublicKey(PublicKey publicKey) {
        this.publicKey = publicKey;
    }

    public PrivateKey getPrivateKey() {
        return privateKey;
    }
    
    public byte[] getEncodedPrivateKey() {
        PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(privateKey.getEncoded());
        return pkcs8EncodedKeySpec.getEncoded();
    }
    
    public String getEncodedPrivateKeyAsString() {
        return Converters.bytesToBase64(getEncodedPrivateKey());
    }

    public void setPrivateKey(PrivateKey privateKey) {
        this.privateKey = privateKey;
    }
    
}

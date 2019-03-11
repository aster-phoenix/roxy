package xyz.pretsa.roxy.symmetric;

import java.util.Base64;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;

/**
 *
 * @author ghazy
 */
public class AESWithGCMKeychain {
    
    private SecretKey secretKey;
    private GCMParameterSpec gcm;
    private byte[] aad;

    public AESWithGCMKeychain(SecretKey secretKey, GCMParameterSpec gcm, byte[] aad) {
        this.secretKey = secretKey;
        this.gcm = gcm;
        this.aad = aad;
    }

    public SecretKey getSecretKey() {
        return secretKey;
    }

    public byte[] getEncodedSecretKey() {
        return secretKey.getEncoded();
    }
    
    public String getEncodedSecretKeyAsString() {
        return Base64.getEncoder().encodeToString(getEncodedSecretKey());
    }
    
    public void setSecretKey(SecretKey secretKey) {
        this.secretKey = secretKey;
    }

    public GCMParameterSpec getGcm() {
        return gcm;
    }
    
    public byte[] getEncodedGcm() {
        return gcm.getIV();
    }
    
    public String getEncodedGcmAsString() {
        return Base64.getEncoder().encodeToString(getEncodedGcm());
    }

    public void setGcm(GCMParameterSpec gcm) {
        this.gcm = gcm;
    }

    public byte[] getAad() {
        return aad;
    }
    
    public String getEncodedAadAsString() {
        return Base64.getEncoder().encodeToString(aad);
    }

    public void setAad(byte[] aad) {
        this.aad = aad;
    }
    
}

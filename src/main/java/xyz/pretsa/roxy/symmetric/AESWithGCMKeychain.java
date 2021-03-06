package xyz.pretsa.roxy.symmetric;

import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import xyz.pretsa.roxy.converter.Converters;

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
        return Converters.bytesToBase64(getEncodedSecretKey());
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
        return Converters.bytesToBase64(getEncodedGcm());
    }

    public void setGcm(GCMParameterSpec gcm) {
        this.gcm = gcm;
    }

    public byte[] getAad() {
        return aad;
    }
    
    public String getEncodedAadAsString() {
        return Converters.bytesToBase64(getAad());
    }

    public void setAad(byte[] aad) {
        this.aad = aad;
    }
    
}

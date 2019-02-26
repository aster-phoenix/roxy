package xyz.pretsa.roxy.symmetric;

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

    public void setSecretKey(SecretKey secretKey) {
        this.secretKey = secretKey;
    }

    public GCMParameterSpec getGcm() {
        return gcm;
    }

    public void setGcm(GCMParameterSpec gcm) {
        this.gcm = gcm;
    }

    public byte[] getAad() {
        return aad;
    }

    public void setAad(byte[] aad) {
        this.aad = aad;
    }
    
}

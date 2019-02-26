/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package xyz.pretsa.roxy.digest;

import java.io.UnsupportedEncodingException;
import java.security.NoSuchAlgorithmException;

/**
 *
 * @author ghazy
 */
public class MessageDigestFacade {
    
    private final String MD5_ALGORITHM = "MD5";
    private final String SHA256_ALGORITHM = "SHA-256";
    private final String SHA512_ALGORITHM = "SHA-512";
    private final MessageDigester digester;

    public MessageDigestFacade() {
       digester = new MessageDigester();
    }
    
    public String hashWithMd5(String msg) throws NoSuchAlgorithmException, UnsupportedEncodingException {
        return digester.hash(msg, MD5_ALGORITHM);
    }

    public String hashWithSha256(String msg) throws NoSuchAlgorithmException, UnsupportedEncodingException {
        return digester.hash(msg, SHA256_ALGORITHM);
    }

    public String hashWithSha512(String msg) throws NoSuchAlgorithmException, UnsupportedEncodingException {
        return digester.hash(msg, SHA512_ALGORITHM);
    }
    
}

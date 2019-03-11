/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package xyz.pretsa.roxy.digest;

import java.io.UnsupportedEncodingException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import xyz.pretsa.roxy.converter.Converters;

/**
 *
 * @author ghazy
 */
public class MessageDigestFacade {

    private final String MD5_ALGORITHM = "MD5";
    private final String SHA256_ALGORITHM = "SHA-256";
    private final String SHA384_ALGORITHM = "SHA-384";
    private final String SHA512_ALGORITHM = "SHA-512";
    private final String UTF_8 = "UTF-8";

    private final MessageDigester digester;

    public MessageDigestFacade() {
        digester = new MessageDigester();
    }

    // MD5
    public byte[] hashWithMd5(String message) throws NoSuchAlgorithmException, UnsupportedEncodingException {
        return digester.hash(message.getBytes(UTF_8), MD5_ALGORITHM);
    }

    public byte[] hashWithMd5(String message, byte[] salt) throws NoSuchAlgorithmException, UnsupportedEncodingException {
        return digester.hash(message.getBytes(UTF_8), salt, MD5_ALGORITHM);
    }

    public String hashWithMd5AsString(String message) throws NoSuchAlgorithmException, UnsupportedEncodingException {
        byte[] hash = digester.hash(message.getBytes(UTF_8), MD5_ALGORITHM);
        return Converters.toBase64(hash);
    }

    public String hashWithMd5AsString(String message, byte[] salt) throws NoSuchAlgorithmException, UnsupportedEncodingException {
        byte[] hash = digester.hash(message.getBytes(UTF_8), salt, MD5_ALGORITHM);
        return Converters.toBase64(hash);
    }

    // SHA-256
    public byte[] hashWithSha256(String message) throws NoSuchAlgorithmException, UnsupportedEncodingException {
        return digester.hash(message.getBytes(UTF_8), SHA256_ALGORITHM);
    }

    public byte[] hashWithSha256(String message, byte[] salt) throws NoSuchAlgorithmException, UnsupportedEncodingException {
        return digester.hash(message.getBytes(UTF_8), salt, SHA256_ALGORITHM);
    }

    public String hashWithSha256AsString(String message) throws NoSuchAlgorithmException, UnsupportedEncodingException {
        byte[] hash = digester.hash(message.getBytes(UTF_8), SHA256_ALGORITHM);
        return Converters.toBase64(hash);
    }

    public String hashWithSha256AsString(String message, byte[] salt) throws NoSuchAlgorithmException, UnsupportedEncodingException {
        byte[] hash = digester.hash(message.getBytes(UTF_8), salt, SHA256_ALGORITHM);
        return Converters.toBase64(hash);
    }

    // SHA-384
    public byte[] hashWithSha384(String message) throws NoSuchAlgorithmException, UnsupportedEncodingException {
        return digester.hash(message.getBytes(UTF_8), SHA384_ALGORITHM);
    }

    public byte[] hashWithSha384(String message, byte[] salt) throws NoSuchAlgorithmException, UnsupportedEncodingException {
        return digester.hash(message.getBytes(UTF_8), salt, SHA384_ALGORITHM);
    }

    public String hashWithSha384AsString(String message) throws NoSuchAlgorithmException, UnsupportedEncodingException {
        byte[] hash = digester.hash(message.getBytes(UTF_8), SHA384_ALGORITHM);
        return Converters.toBase64(hash);
    }

    public String hashWithSha384AsString(String message, byte[] salt) throws NoSuchAlgorithmException, UnsupportedEncodingException {
        byte[] hash = digester.hash(message.getBytes(UTF_8), salt, SHA384_ALGORITHM);
        return Converters.toBase64(hash);
    }

    // SHA-512
    public byte[] hashWithSha512(String message) throws NoSuchAlgorithmException, UnsupportedEncodingException {
        return digester.hash(message.getBytes(UTF_8), SHA512_ALGORITHM);
    }

    public byte[] hashWithSha512(String message, byte[] salt) throws NoSuchAlgorithmException, UnsupportedEncodingException {
        return digester.hash(message.getBytes(UTF_8), salt, SHA512_ALGORITHM);
    }

    public String hashWithSha512AsString(String message) throws NoSuchAlgorithmException, UnsupportedEncodingException {
        byte[] hash = digester.hash(message.getBytes(UTF_8), SHA512_ALGORITHM);
        return Converters.toBase64(hash);
    }

    public String hashWithSha512AsString(String message, byte[] salt) throws NoSuchAlgorithmException, UnsupportedEncodingException {
        byte[] hash = digester.hash(message.getBytes(UTF_8), salt, SHA512_ALGORITHM);
        return Converters.toBase64(hash);
    }

    // PBKDF
    public byte[] hashWithPBKDF2(String message, byte[] salt) throws InvalidKeySpecException, NoSuchAlgorithmException {
        return digester.PBKDF2Hash(message.toCharArray(), salt);
    }

    public String hashWithPBKDF2AsString(String message, byte[] salt) throws InvalidKeySpecException, NoSuchAlgorithmException {
        byte[] hash = digester.PBKDF2Hash(message.toCharArray(), salt);
        return Converters.toBase64(hash);
    }

    public byte[] hashWithPBKDF2(String message, byte[] salt, int iterations, int keySize) throws InvalidKeySpecException, NoSuchAlgorithmException {
        return digester.PBKDF2Hash(message.toCharArray(), salt, iterations, keySize);
    }

    public String hashWithPBKDF2AsString(String message, byte[] salt, int iterations, int keySize) throws InvalidKeySpecException, NoSuchAlgorithmException {
        byte[] hash = digester.PBKDF2Hash(message.toCharArray(), salt, iterations, keySize);
        return Converters.toBase64(hash);
    }

}

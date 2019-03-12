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

    private final MessageDigester digester;

    public MessageDigestFacade() {
        digester = new MessageDigester();
    }

    // MD5
    public String hashWithMd5AsString(String message) throws NoSuchAlgorithmException, UnsupportedEncodingException {
        byte[] messageBytes = Converters.stringToBytes(message);
        byte[] hash = hashWithMd5(messageBytes);
        return Converters.bytesToBase64(hash);
    }

    public byte[] hashWithMd5(byte[] message) throws NoSuchAlgorithmException, UnsupportedEncodingException {
        return digester.hash(message, MD5_ALGORITHM);
    }

    public String hashWithMd5AsString(String message, byte[] salt) throws NoSuchAlgorithmException, UnsupportedEncodingException {
        byte[] messageBytes = Converters.stringToBytes(message);
        byte[] hash = hashWithMd5(messageBytes, salt);
        return Converters.bytesToBase64(hash);
    }

    public byte[] hashWithMd5(byte[] message, byte[] salt) throws NoSuchAlgorithmException, UnsupportedEncodingException {
        return digester.hash(message, salt, MD5_ALGORITHM);
    }

    // SHA-256
    public String hashWithSha256AsString(String message) throws NoSuchAlgorithmException, UnsupportedEncodingException {
        byte[] messageBytes = Converters.stringToBytes(message);
        byte[] hash = hashWithSha256(messageBytes);
        return Converters.bytesToBase64(hash);
    }

    public byte[] hashWithSha256(byte[] message) throws NoSuchAlgorithmException, UnsupportedEncodingException {
        return digester.hash(message, SHA256_ALGORITHM);
    }

    public String hashWithSha256AsString(String message, byte[] salt) throws NoSuchAlgorithmException, UnsupportedEncodingException {
        byte[] messageBytes = Converters.stringToBytes(message);
        byte[] hash = hashWithSha256(messageBytes, salt);
        return Converters.bytesToBase64(hash);
    }

    public byte[] hashWithSha256(byte[] message, byte[] salt) throws NoSuchAlgorithmException, UnsupportedEncodingException {
        return digester.hash(message, salt, SHA256_ALGORITHM);
    }

    // SHA-384
    public String hashWithSha384AsString(String message) throws NoSuchAlgorithmException, UnsupportedEncodingException {
        byte[] messageBytes = Converters.stringToBytes(message);
        byte[] hash = hashWithSha384(messageBytes);
        return Converters.bytesToBase64(hash);
    }

    public byte[] hashWithSha384(byte[] message) throws NoSuchAlgorithmException, UnsupportedEncodingException {
        return digester.hash(message, SHA384_ALGORITHM);
    }
    public String hashWithSha384AsString(String message, byte[] salt) throws NoSuchAlgorithmException, UnsupportedEncodingException {
        byte[] messageBytes = Converters.stringToBytes(message);
        byte[] hash = hashWithSha384(messageBytes, salt);
        return Converters.bytesToBase64(hash);
    }
    public byte[] hashWithSha384(byte[] message, byte[] salt) throws NoSuchAlgorithmException, UnsupportedEncodingException {
        return digester.hash(message, salt, SHA384_ALGORITHM);
    }

    // SHA-512
    public String hashWithSha512AsString(String message) throws NoSuchAlgorithmException, UnsupportedEncodingException {
        byte[] messageBytes = Converters.stringToBytes(message);
        byte[] hash = hashWithSha512(messageBytes);
        return Converters.bytesToBase64(hash);
    }
    public byte[] hashWithSha512(byte[] message) throws NoSuchAlgorithmException, UnsupportedEncodingException {
        return digester.hash(message, SHA512_ALGORITHM);
    }

    public String hashWithSha512AsString(String message, byte[] salt) throws NoSuchAlgorithmException, UnsupportedEncodingException {
        byte[] messageBytes = Converters.stringToBytes(message);
        byte[] hash = hashWithSha512(messageBytes, salt);
        return Converters.bytesToBase64(hash);
    }
    public byte[] hashWithSha512(byte[] message, byte[] salt) throws NoSuchAlgorithmException, UnsupportedEncodingException {
        return digester.hash(message, salt, SHA512_ALGORITHM);
    }

    // PBKDF
    public String hashWithPBKDF2AsString(String message, byte[] salt) throws InvalidKeySpecException, NoSuchAlgorithmException {
        byte[] hash = hashWithPBKDF2(message.toCharArray(), salt);
        return Converters.bytesToBase64(hash);
    }

    public byte[] hashWithPBKDF2(char[] message, byte[] salt) throws InvalidKeySpecException, NoSuchAlgorithmException {
        return digester.PBKDF2Hash(message, salt);
    }

    public String hashWithPBKDF2AsString(String message, byte[] salt, int iterations, int keySize) throws InvalidKeySpecException, NoSuchAlgorithmException {
        byte[] hash = hashWithPBKDF2(message.toCharArray(), salt, iterations, keySize);
        return Converters.bytesToBase64(hash);
    }

    public byte[] hashWithPBKDF2(char[] message, byte[] salt, int iterations, int keySize) throws InvalidKeySpecException, NoSuchAlgorithmException {
        return digester.PBKDF2Hash(message, salt, iterations, keySize);
    }

}

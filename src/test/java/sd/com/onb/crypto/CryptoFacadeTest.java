/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package sd.com.onb.crypto;

import org.junit.BeforeClass;
import org.junit.Test;

/**
 *
 * @author Ghazy
 */
public class CryptoFacadeTest {
    
    private static final String msg = "Aster Phoenix!";
    
    @BeforeClass
    public static void setUp() {
//        System.out.println("original : " + msg);
//        CryptoFacade.generateAndSaveDefaultKeys();
    }
    
    @Test
    public void testAes() {
//        String encrptedMsg = CryptoFacade.aesEncrypt(msg);
//        System.out.println("AES Encrpted : " + encrptedMsg);
//        Assert.assertNotNull(encrptedMsg);
//        String decryptedMsg = CryptoFacade.aesDecrypt(encrptedMsg);
//        System.out.println("AES Decrpted : " + decryptedMsg);
//        Assert.assertNotNull(decryptedMsg);
//        Assert.assertEquals(msg, decryptedMsg);
    }
    
    @Test
    public void testRsaEncryptionDecryption() {
//        String encrptedMsg = CryptoFacade.rsaEncrypt(msg);
//        System.out.println("RSA Encrpted : " + encrptedMsg);
//        Assert.assertNotNull(encrptedMsg);
//        String decryptedMsg = CryptoFacade.rsaDecrypt(encrptedMsg);
//        System.out.println("RSA Decrpted : " + decryptedMsg);
//        Assert.assertNotNull(decryptedMsg);
//        Assert.assertEquals(msg, decryptedMsg);
    }
    
    @Test
    public void testRsaSignVerify() {
//        String signature = CryptoFacade.rsaSignWithSHA512(msg);
//        System.out.println("RSA Signed : " + signature);
//        Assert.assertNotNull(signature);
//        boolean r = CryptoFacade.rsaVerifyWithSHA512(msg, signature);
//        Assert.assertTrue(r);
//        System.out.println("RSA Verified : " + r);
   }
    
}

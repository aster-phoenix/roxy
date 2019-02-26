/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package xyz.pretsa.roxy.symmetric;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import static org.junit.Assert.*;

/**
 *
 * @author ghazy
 */
public class AESWithGCMCipherFacadeTest {

    AESWithGCMCipherFacade facade;

    @Before
    public void setUp() {
        facade = new AESWithGCMCipherFacade();
    }

    @After
    public void tearDown() {
    }

    @Test
    public void testAESEncryptionDecriptionWithMinimalKeychain() {
        try {
            AESWithGCMKeychain keyChain = AESWithGCMKeychainBuilder.newMinimalKeychain();
            String original = "Ghazy";
            String encryptedString = facade.encryptString(original, keyChain);
            String decryptedString = facade.decryptString(encryptedString, keyChain);
            assertEquals(decryptedString, original);
        } catch (Exception e) {
            e.printStackTrace();
            fail(e.getMessage());
        }
    }

}

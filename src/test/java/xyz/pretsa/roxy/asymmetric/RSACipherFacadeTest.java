/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package xyz.pretsa.roxy.asymmetric;

import org.junit.Before;
import org.junit.Test;
import static org.junit.Assert.*;

/**
 *
 * @author ghazy
 */
public class RSACipherFacadeTest {
    
    RSACipherFacade facade;
    
    @Before
    public void setUp() {
        facade = new RSACipherFacade();
    }

    /**
     * Test of encryptString method, of class RSACipherFacade.
     */
    @Test
    public void testRSAEncryptionDecriptionWithDefaultKeychain() {
        try {
            RSAKeychain keyChain = RSAKeychainBuilder.withNewKeyPair();
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

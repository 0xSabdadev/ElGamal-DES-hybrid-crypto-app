/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

package cryptosystem.keyencapsulation;

import java.math.BigInteger;
import java.security.SecureRandom;

/**
 * Class for Key Encryption using ElGamal algorithm.
 * 
 * @author Zaylin
 */
public class KeyDecryption {

    /**
     * Constructor.Decrypts cipher message using public key and returns the secret
     * key message.
     * 
     * @param c    cipher message of key.
     * @param priK private key to use.
     * @param p    prime.
     */
    public KeyDecryption(CipherText c, BigInteger priK, BigInteger p) {
        // r=c1^(secretKey)mod p
        BigInteger r = c.getCipher1().modPow(priK, p);
        // m=r*c2 mod p
        BigInteger m = r.multiply(c.getCipher2()).mod(p);
        kMsg = m.toString(16);
    }

    /**
     * Get key message in Hex.
     * 
     * @return message
     */
    public String getKeyMsg() {
        return kMsg;
    }

    private CipherText c;
    private String kMsg;
}

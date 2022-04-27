/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

package cryptosystem.keyencapsulation;

import java.math.BigInteger;

/**
 * Class for cipherText object.
 * 
 * @author Zaylin
 */
public class CipherText {

    /**
     * Default Constructor. Sets c1 and c2 to zero.
     */
    public CipherText() {
        c1 = BigInteger.ZERO;
        c2 = BigInteger.ZERO;
    }

    /**
     * Constructor.
     * 
     * @param ct1 value for g^k(mod p).
     * @param ct2 value for m*(q)^k(mod p).
     */
    public CipherText(BigInteger ct1, BigInteger ct2) {
        c1 = ct1;
        c2 = ct2;
    }

    /**
     * Gets first part of the cipher.
     * 
     * @return cipher first part.
     */
    public BigInteger getCipher1() {
        return c1;
    }

    /**
     * Gets second part of the cipher.
     * 
     * @return cipher second part.
     */
    public BigInteger getCipher2() {
        return c2;
    }

    /**
     * Convert cipher text to string.
     * 
     * @return hex string.
     */
    public String toHex() {
        String str1 = c1.toString(16);
        String str2 = c2.toString(16);
        return str1 + str2;
    }

    private final BigInteger c1;
    private final BigInteger c2;
}

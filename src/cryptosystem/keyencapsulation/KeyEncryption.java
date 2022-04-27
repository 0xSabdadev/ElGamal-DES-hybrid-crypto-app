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
public class KeyEncryption {

    /**
     * Constructor. Encrypts key message using public key and returns the cipher
     * message.
     * 
     * @param keyMsg message to encrypt for key.
     * @param pubKey public key to use.
     */
    public KeyEncryption(String keyMsg, PublicKey pubKey) {
        BigInteger p = pubKey.getP();
        BigInteger g = pubKey.getG();
        BigInteger q = pubKey.getQ();
        // conver M into integers in p
        BigInteger m = new BigInteger(1, keyMsg.getBytes());
        // select random k between 1 and p-2
        BigInteger k = new BigInteger(p.bitLength() - 2, new SecureRandom());
        // check if k ==0. If it is zero add 1.
        if (k.compareTo(BigInteger.ZERO) == 0) {
            k.add(BigInteger.ONE);
        }
        // compute g^k(mod p)
        BigInteger c1 = g.modPow(k, p);
        // compute m*(q)^k(mod p)
        BigInteger c2 = m.multiply(q.modPow(k, p));
        c = new CipherText(c1, c2);
        kMsg = keyMsg;
    }

    /**
     * Get cipher message.
     * 
     * @return cipher object.
     */
    public CipherText getCipher() {
        return c;
    }

    /**
     * Get key message.
     * 
     * @return message
     */
    public String getKeyMsg() {
        return kMsg;
    }

    private CipherText c;
    private String kMsg;
}

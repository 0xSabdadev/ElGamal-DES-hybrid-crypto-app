/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

package cryptosystem.keyencapsulation;

import java.math.BigInteger;
import java.util.ArrayList;

/**
 * Class to define public key object.
 * 
 * @author Zaylin
 */
public class PublicKey {

    /**
     * Constructor for public key
     * 
     * @param pubKey array of public key. Must be in the order of prime,generator,
     *               generator^secret key (mod prime)
     */
    public PublicKey(ArrayList<BigInteger> pubKey) {
        p = pubKey.get(0);
        g = pubKey.get(1);
        q = pubKey.get(2);
    }

    /**
     * Constructor for public key.
     * 
     * @param pVal prime.
     * @param gVal generator.
     * @param qVal generator^secret key (mod prime).
     */
    public PublicKey(BigInteger pVal, BigInteger gVal, BigInteger qVal) {
        p = pVal;
        g = gVal;
        q = qVal;
    }

    /**
     * Return value for prime.
     * 
     * @return BigInteger prime.
     */
    public BigInteger getP() {
        return p;
    }

    /**
     * Return value for generator.
     * 
     * @return BigInteger generator.
     */
    public BigInteger getG() {
        return g;
    }

    /**
     * Return value for q=generator^secret key (mod prime).
     * 
     * @return BigInteger q.
     */
    public BigInteger getQ() {
        return q;
    }

    /**
     * Sets a new value for the generator.
     * 
     * @param newG new value for generator.
     */
    public void setG(BigInteger newG) {
        g = newG;
    }

    /**
     * Sets a new value for the q.
     * 
     * @param newQ new value for q.
     */
    public void setQ(BigInteger newQ) {
        q = newQ;
    }

    private final BigInteger p;
    private BigInteger g;
    private BigInteger q;
}

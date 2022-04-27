/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

package cryptosystem.keyencapsulation;

import java.math.BigInteger;
import java.security.SecureRandom;

/**
 * Class for Public and Private Key Generator using ElGamal algorithm.
 * 
 * @author Zaylin
 */
public class KeyGenerator {

    /**
     * Constructor.
     */
    public KeyGenerator() {
        // get prime number
        p = generatePrimeNumber();
        // select g
        g = generateG();
        // select secret key
        priK = generatePriK();
        // calculate q
        q = calculateQ();
        pubK = new PublicKey(p, g, q);
        secretMsg = "Password";
    }

    /**
     * Constructor.
     * 
     * @param msg secret key message.
     */
    public KeyGenerator(String msg) {
        // get prime number
        p = generatePrimeNumber();
        // select g
        g = generateG();
        // select secret key
        priK = generatePriK();
        // calculate q
        q = calculateQ();
        pubK = new PublicKey(p, g, q);
        secretMsg = msg;
    }

    /**
     * Calculate q values using prime number, public key, and the generator.
     * 
     * @return q value.
     */
    private BigInteger calculateQ() {
        // g^privK (mod p)
        BigInteger t = g.modPow(priK, p);
        return t;
    }

    /**
     * Select private key.
     * 
     * @return private key.
     */
    private BigInteger generatePriK() {
        // select random t between 0 and p-2.
        BigInteger t = new BigInteger(p.subtract(new BigInteger("2")).bitCount(), new SecureRandom());
        // add 1 if 0.
        if (t.compareTo(BigInteger.ONE) == 1) {
            t.add(BigInteger.ONE);
        }
        return t;
    }

    /**
     * Select random generator using prime number.
     * 
     * @return g generator.
     */
    private BigInteger generateG() {
        boolean isGenerated = false;
        // select random h, 2<= g <= p-1
        BigInteger h = new BigInteger(p.subtract(BigInteger.ONE).bitCount(), new SecureRandom());
        // if h <= 1
        if (h.compareTo(BigInteger.ONE) == 1) {
            h.add(BigInteger.ONE);
        }
        while (!isGenerated) {
            // check h^(p-1)/q mod p != 1 then g = h^(p-1)/q mod p
            BigInteger check = h.modPow((p.subtract(BigInteger.ONE)).divide(new BigInteger("2")), p);
            if (!check.equals(BigInteger.ONE)) {
                isGenerated = true;
            } else {
                // select random h, 2<= g <= p-1
                h = new BigInteger(p.subtract(BigInteger.ONE).bitCount(), new SecureRandom());
                // if h <= 1
                if (h.compareTo(BigInteger.ONE) == 1) {
                    h.add(BigInteger.ONE);
                }
            }
        }
        return h;
    }

    /**
     * Generates Prime Number using Java Secure Random Generator.
     * 
     * @return prime number.
     */
    private BigInteger generatePrimeNumber() {
        BigInteger prime = BigInteger.probablePrime(256, new SecureRandom());
        // check if random
        while (RabinMillerTest(prime) != true) {
            prime = BigInteger.probablePrime(256, new SecureRandom());
        }
        return prime;
    }

    /**
     * Uses java Rabin Miller Primality test to test if the prime number is prime.
     * 
     * @param prime number to test
     * @return true if prime, false otherwise.
     */
    private boolean RabinMillerTest(BigInteger prime) {
        return prime.isProbablePrime(1);
    }

    /**
     * Gets the Public Key.
     * 
     * @return public key.
     */
    public PublicKey getPublicKey() {
        return pubK;
    }

    /**
     * Recalculates g generator, and q value.
     * 
     * @return new public key.
     */
    public PublicKey recalculateG() {
        // select g
        BigInteger t = generateG();
        do {
            t = generateG();
        } while (t.equals(g) == true && t.equals(p) == true);
        g = t;
        pubK.setG(g);
        // calculate q
        q = calculateQ();
        pubK.setQ(q);
        return pubK;
    }

    /**
     * Update the secret key message
     * 
     * @param msg new secret key message.
     */
    public void updateSecretMsg(String msg) {
        secretMsg = msg;
    }

    /**
     * Gets key Message.
     * 
     * @return string of message
     */
    public String getKeyMsg() {
        return secretMsg;
    }

    /**
     * Gets private key for decryption.
     * 
     * @return string of message
     */
    public BigInteger getPrivateKey() {
        return priK;
    }

    // class variables
    private final BigInteger priK;
    private PublicKey pubK;
    private final BigInteger p;
    private BigInteger g;
    private BigInteger q;
    private String secretMsg;
}

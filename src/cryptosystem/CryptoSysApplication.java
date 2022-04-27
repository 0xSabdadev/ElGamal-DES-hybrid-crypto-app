/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

package cryptosystem;

import cryptosystem.dataencapsulation.BlockDecoder;
import cryptosystem.dataencapsulation.BlockEncoder;
import cryptosystem.dataencapsulation.ECB;
import cryptosystem.dataencapsulation.KeyGeneratorD;
import cryptosystem.keyencapsulation.CipherText;
import cryptosystem.keyencapsulation.KeyDecryption;
import cryptosystem.keyencapsulation.KeyEncryption;
import cryptosystem.keyencapsulation.KeyGenerator;
import cryptosystem.keyencapsulation.PublicKey;
import java.math.BigInteger;
import java.util.List;
import java.util.Scanner;

/**
 * Console interface for cryptosystem application.
 * 
 * @author Zaylin
 */
public class CryptoSysApplication {

    /**
     * Main function.
     * 
     * @param args the command line arguments
     */
    public static void main(String[] args) {
        ECB ecb = new ECB();
        KeyGenerator key = new KeyGenerator();
        String lpw;
        CipherText ctObj = new CipherText();
        String plaintext;
        String ciphertext;
        String secretKeyMsg;
        boolean repeat = false;
        try (Scanner reader = new Scanner(System.in).useDelimiter("\n")) {
            do {
                System.out.println("Main menu.\n 1---To Encrypt Message\n 2---To Decrypt Message.");
                int ch1;
                if (System.console() == null) {
                    ch1 = reader.nextInt();
                } else {
                    ch1 = Integer.parseInt(System.console().readLine());
                }
                if (ch1 == 1) {
                    // encrypt
                    System.out.println(
                            "Please enter message to encrypt.If message is in hex, please add # to the begining.");
                    if (System.console() == null) {
                        plaintext = reader.next();
                    } else {
                        plaintext = System.console().readLine();
                    }
                    System.out.println("Please enter secret key. It must be a hexadecimal string.");
                    if (System.console() == null) {
                        secretKeyMsg = reader.next();
                    } else {
                        secretKeyMsg = System.console().readLine();
                    }
                    encryptMessage(key, plaintext, secretKeyMsg, ecb, ctObj);
                    System.out.println("C---To continue. S---To stop.");
                    String ch2;
                    if (System.console() == null) {
                        ch2 = reader.next();
                    } else {
                        ch2 = System.console().readLine();
                    }
                    repeat = checkRepeat(ch2);
                } else if (ch1 == 2) {
                    // decrypt
                    System.out.println("Please enter message to decrypt. Message must be a hexadecimal string.");
                    if (System.console() == null) {
                        ciphertext = reader.next();
                    } else {
                        ciphertext = System.console().readLine();
                    }
                    decryptMessage(key, ciphertext, ecb, ctObj);
                    System.out.println("C---To continue. S---To stop.");
                    String ch2;
                    if (System.console() == null) {
                        ch2 = reader.next();
                    } else {
                        ch2 = System.console().readLine();
                    }
                    repeat = checkRepeat(ch2);
                } else {
                    System.out.println("Please select a correct option. Encrypt = 1; Decrypt = 2.");
                    repeat = true;
                }
            } while (repeat);
            reader.close();
        }
    }

    /**
     * Encrypts message using ElGamal and DES Uses secret key message and ElGamal to
     * create key Then uses encrypted key to encrypt the message using DES.
     * 
     * @param key   key generator object.
     * @param msg   message to encrypt.
     * @param pw    secret message for the key.
     * @param ecb   electronic codebook variable.
     * @param ctObj ciphertext object to add key encryption results.
     * @return -1 if the plaintext and secretKey are not empty. Otherwise returns 0.
     */
    public static int encryptMessage(KeyGenerator key, String msg, String pw, ECB ecb, CipherText ctObj) {
        PublicKey pk = key.getPublicKey();
        KeyEncryption ke = new KeyEncryption(pw, pk);
        CipherText c = ke.getCipher();
        ctObj = c;
        String cHex = c.toHex();
        if (!"".equals(msg)) {
            List<String> blocks;
            KeyGeneratorD keyGen = new KeyGeneratorD(cHex);
            String[] enckeys = keyGen.generateEKeys();
            // System.out.println(Arrays.toString(enckeys));
            BlockEncoder be = new BlockEncoder(enckeys);
            blocks = ecb.createStringBlocks(msg);
            System.out.println("Plaintext in hexadecimal blocks: " + blocks.toString());
            String cipherText = "";
            for (int i = 0; i < blocks.size(); i++) {
                String temp = be.encodeBlock(blocks.get(i));
                cipherText += temp;
            }
            System.out.println("The ciphertext is: " + cipherText);
            return 0;
        } else {
            return -1;
        }
    }

    /**
     * Decrypts message using ElGamal and DES Uses secret key message and ElGamal to
     * create key Then uses encrypted key to encrypt the message using DES.
     * 
     * @param key   key generator object.
     * @param ct    ciphertext. Text to decrypt.
     * @param ecb   electronic codebook variable.
     * @param ctObj ciphertext object to get key encryption results.
     * @return -1 if the ciphertext and secretKey are not empty. Otherwise returns
     *         0.
     */
    public static int decryptMessage(KeyGenerator key, String ct, ECB ecb, CipherText ctObj) {
        BigInteger pk = key.getPrivateKey();
        BigInteger p = key.getPublicKey().getP();
        KeyDecryption kd = new KeyDecryption(ctObj, pk, p);
        String kHex = kd.getKeyMsg();
        if (!"".equals(ct)) {
            List<String> blocks;
            KeyGeneratorD keyGen = new KeyGeneratorD(kHex);
            String[] deckeys = keyGen.generateDKeys();
            // System.out.println(Arrays.toString(deckeys));
            BlockDecoder bd = new BlockDecoder(deckeys);
            blocks = ecb.createHexBlocks(ct.trim());
            System.out.println("Hexadecimal blocks: " + blocks.toString());
            String plainText = "";
            for (int i = 0; i < blocks.size(); i++) {
                String temp = bd.decodeBlock(blocks.get(i));
                // String temp2 = ecb.hexToString(temp);
                plainText += temp;
            }
            plainText = ecb.hexToString(plainText);
            System.out.println("This is the plaintext: " + plainText);
            return 0;
        } else {
            return -1;
        }
    }

    /**
     * Checks if the program will continue or stop.
     * 
     * @param s option selected.
     * @return Returns true if s="C" or "c". Otherwise returns false;
     */
    public static boolean checkRepeat(String s) {
        if (null == s) {
            return false;
        } else {
            switch (s.toUpperCase()) {
                case "C":
                    return true;
                case "S":
                    return false;
                default:
                    return false;
            }
        }
    }
}

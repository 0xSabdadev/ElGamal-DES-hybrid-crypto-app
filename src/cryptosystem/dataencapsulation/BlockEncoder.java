/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

package cryptosystem.dataencapsulation;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;

/**
 * Class to encode 64 bit blocks using DES.
 * 
 * @author Zaylin Arata
 */
public class BlockEncoder {
    /**
     * Encodes a blocks.
     * 
     * @param s block string.
     * @return a hex string of the ciphertext.
     */
    public String encodeBlock(String s) {
        // convert to to binay string
        String b = new BigInteger(s, 16).toString(2);
        // add padding to begining
        while (b.length() % 64 != 0) {
            b = '0' + b;
        }
        char[] ip = new char[IP.length + 1];
        char[] block = b.toCharArray();
        // first permutation
        for (int i = 0; i < IP.length; i++) {
            // System.out.println("i="+ i +" IP POS=" + IP[i] +" Value="+block[IP[i]-1]);
            ip[i] = block[IP[i] - 1];
        }
        String sPI1 = new String(ip);
        String li = sPI1.substring(0, (sPI1.length() / 2));
        String ri = sPI1.substring((sPI1.length() / 2));
        ri = ri.trim();
        L[0] = li;
        R[0] = ri;
        for (int i = 1; i < 17; i++) {
            L[i] = R[i - 1];
            // do R expansion
            String exp = expansion(R[i - 1].toCharArray());
            // do XOR of Key and R
            String xor = myXOR(exp, K[i]);
            while (xor.length() % 48 != 0) {
                xor = '0' + xor;
            }
            // do S-box
            String sbox = sBox(xor);
            while (sbox.length() % 32 != 0) {
                sbox = '0' + sbox;
            }
            String temp = myXOR(L[i - 1], sbox);
            while (temp.length() % 32 != 0) {
                temp = '0' + temp;
            }
            R[i] = temp;
        }
        // final permutation
        String bCipher = finalPermutation();
        // convert binary cipher list to hext
        String hCipher = cipherToHex(bCipher);
        return hCipher;
    }

    /**
     * Converts ciphertext to hex string.
     * 
     * @param c ciphertext string to convert.
     * @return a hex string.
     */
    private String cipherToHex(String c) {
        String hCipher = "";
        String p1 = c.substring(0, 32);
        String p2 = c.substring(32);
        long n1 = Long.parseLong(p1, 2);
        String temp1 = Long.toHexString(n1);
        long n2 = Long.parseLong(p2, 2);
        String temp2 = Long.toHexString(n2);
        hCipher += temp1 + "" + temp2 + " ";
        return hCipher;
    }

    /**
     * Final permutation function using table IP_1 (IP^1).
     * 
     * @return String with final permutation.
     */
    private String finalPermutation() {
        // String bcipher = "";
        String s = R[16] + "" + L[16];
        char[] arr = s.toCharArray();
        char[] ip1 = new char[IP_1.length];
        for (int j = 0; j < IP_1.length; j++) {
            ip1[j] = arr[IP_1[j] - 1];
        }
        String temp = new String(ip1);
        return temp;
    }

    /**
     * Creates the s-box and calls the s-box permutation function.
     * 
     * @param s xor string
     * @return s-box string with permutation.
     */
    private String sBox(String s) {
        // create s blocks
        int sBlocks = s.length() / 6;
        List<String> blocks = new ArrayList();
        int count = 0;
        // make blocks
        while (sBlocks != blocks.size()) {
            String temp = s.substring(count, count + 6);
            blocks.add(temp);
            count = count + 6;
        }
        String res = "";
        for (int i = 0; i < blocks.size(); i++) {
            String sRow = blocks.get(i).charAt(0) + "" + blocks.get(i).charAt(5);
            String sCol = blocks.get(i).substring(1, 5);
            int row = Integer.parseInt(sRow.trim(), 2);
            int col = Integer.parseInt(sCol.trim(), 2);
            int val = 0;
            switch (i + 1) {
                case 1:
                    val = S1[row][col];
                    break;
                case 2:
                    val = S2[row][col];
                    break;
                case 3:
                    val = S3[row][col];
                    break;
                case 4:
                    val = S4[row][col];
                    break;
                case 5:
                    val = S5[row][col];
                    break;
                case 6:
                    val = S6[row][col];
                    break;
                case 7:
                    val = S7[row][col];
                    break;
                case 8:
                    val = S8[row][col];
                    break;
            }
            String temp = Integer.toBinaryString(val);
            while (temp.length() < 4) {
                temp = "0" + temp;
            }
            res += temp;
        }
        while (res.length() % 32 != 0) {
            res = "0" + res;
        }
        // System.out.println("S-Box" +res.length());
        String perm = sBoxPermutation(res.toCharArray());
        return perm;
    }

    /**
     * Permutation of s-boxes.
     * 
     * @param sBox array of box for permutation.
     * @return String with S-box permutation.
     */
    private String sBoxPermutation(char[] sBox) {
        char[] sExp = new char[P.length];
        for (int i = 0; i < P.length; i++) {
            sExp[i] = sBox[P[i] - 1];
        }
        String res = new String(sExp);
        return res;
    }

    /**
     * Expansion function using E-table.
     * 
     * @param arr array to expand.
     * @return Expanded string.
     */
    private String expansion(char[] arr) {
        char[] exp = new char[E.length];
        for (int i = 0; i < E.length; i++) {
            exp[i] = arr[E[i] - 1];
        }
        String res = new String(exp);
        // System.out.println("Expansion" + res.length());
        return res;
    }

    /**
     * XOR implementation.
     * 
     * @param r right side of string
     * @param k key string
     * @return XOR string.
     */
    private String myXOR(String r, String k) {
        BigInteger rBin = new BigInteger(r.trim(), 2);
        BigInteger kBin = new BigInteger(k.trim(), 2);
        BigInteger res = rBin.xor(kBin);
        String s = res.toString(2);
        // System.out.println("XOR" + s.length());
        return s;
    }

    /**
     * Class constructor for Block Encoder.
     * 
     * @param arr
     */
    public BlockEncoder(String[] arr) {
        K = arr;
    }

    // class variables
    private final int[] IP = { 58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4, 62, 54, 46, 38, 30, 22, 14,
            6, 64, 56, 48, 40, 32, 24, 16, 8, 57, 49, 41, 33, 25, 17, 9, 1, 59, 51, 43, 35, 27, 19, 11, 3, 61, 53, 45,
            37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7 };
    private final int[] IP_1 = { 40, 8, 48, 16, 56, 24, 64, 32, 39, 7, 47, 15, 55, 23, 63, 31, 38, 6, 46, 14, 54, 22,
            62, 30, 37, 5, 45, 13, 53, 21, 61, 29, 36, 4, 44, 12, 52, 20, 60, 28, 35, 3, 43, 11, 51, 19, 59, 27, 34, 2,
            42, 10, 50, 18, 58, 26, 33, 1, 41, 9, 49, 17, 57, 25 };
    private final int[] P = { 16, 7, 20, 21, 29, 12, 28, 17, 1, 15, 23, 26, 5, 18, 31, 10, 2, 8, 24, 14, 32, 27, 3, 9,
            19, 13, 30, 6, 22, 11, 4, 25 };
    private final int[] E = { 32, 1, 2, 3, 4, 5, 4, 5, 6, 7, 8, 9, 8, 9, 10, 11, 12, 13, 12, 13, 14, 15, 16, 17, 16, 17,
            18, 19, 20, 21, 20, 21, 22, 23, 24, 25, 24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32, 1 };
    private final int[][] S1 = { { 14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7 },
            { 0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8 },
            { 4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0 },
            { 15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13 } };
    private final int[][] S2 = { { 15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10 },
            { 3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5 },
            { 0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15 },
            { 13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9 } };
    private final int[][] S3 = { { 10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8 },
            { 13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1 },
            { 13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7 },
            { 1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12 } };
    private final int[][] S4 = { { 7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15 },
            { 13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9 },
            { 10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4 },
            { 3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14 } };
    private final int[][] S5 = { { 2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9 },
            { 14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6 },
            { 4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14 },
            { 11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3 } };
    private final int[][] S6 = { { 12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11 },
            { 10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8 },
            { 9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6 },
            { 4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13 } };
    private final int[][] S7 = { { 4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1 },
            { 13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6 },
            { 1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2 },
            { 6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12 } };
    private final int[][] S8 = { { 13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7 },
            { 1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2 },
            { 7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8 },
            { 2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11 } };
    private String[] L = new String[17];
    private String[] R = new String[17];
    private String[] K = new String[17];
}

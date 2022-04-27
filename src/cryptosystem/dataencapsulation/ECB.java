/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

package cryptosystem.dataencapsulation;

import java.util.ArrayList;
import java.util.List;
import javax.xml.bind.DatatypeConverter;

/**
 * Class for Electronic Code Book Mode (ECB) implementation.
 * 
 * @author Zaylin Arata
 */
public class ECB {

    /**
     * Converts a string to hex string.
     * 
     * @param s string to convert
     * @return a hex string
     */
    public String toHexString(String s) {
        byte[] sbytes = s.getBytes();
        StringBuilder strHex = new StringBuilder();

        for (int i = 0; i < sbytes.length; i++) {
            String hex = Integer.toHexString(0xFF & sbytes[i]);
            if (hex.length() == 1) {
                strHex.append('0');
            }
            strHex.append(hex);
        }
        String result = strHex.toString();
        // add padding to end
        while (result.length() % 16 != 0) {
            result += '0';
        }
        return result;
    }

    /**
     * Converts hex string into a string.
     * 
     * @param s hex string to convert.
     * @return a string
     */
    public String hexToString(String s) {
        String[] str = s.split(" ");
        String res = "";
        for (int i = 0; i < str.length; i++) {
            while (str[i].length() % 2 != 0) {
                str[i] = str[i] + '0';
            }
            byte[] b = DatatypeConverter.parseHexBinary(str[i]);
            // System.out.println(new String(b));
            String t = new String(b);
            res += t;
        }
        return res;
    }

    /**
     * Create Blocks from a string.
     * 
     * @param s string to create blocks from
     * @return List of hex string.
     */
    public List<String> createStringBlocks(String s) {
        String str = toHexString(s);
        nBlocks = str.length() / 16;

        int count = 0;
        // make blocks
        while (nBlocks != blocks.size() && (count / 16) <= nBlocks) {
            if (str.length() >= count + 16) {
                String temp = str.substring(count, count + 16);
                blocks.add(temp);
                count = count + 16;
            }
        }
        return blocks;
    }

    /**
     * Create Blocks from a hex string.
     * 
     * @param s string to create blocks from
     * @return List of hex string.
     */
    public List<String> createHexBlocks(String s) {
        String str = s;
        while (str.length() % 16 != 0) {
            str += '0';
        }
        nBlocks = str.length() / 16;

        int count = 0;
        // make blocks
        while (nBlocks != blocks.size()) {
            String temp = str.substring(count, count + 16);
            blocks.add(temp);
            count = count + 16;
        }
        return blocks;
    }

    /**
     * Constructor for ECB Object.
     */
    public ECB() {
        nBlocks = 0;
        blocks = new ArrayList();
    }

    // class variables
    private int nBlocks;
    private List<String> blocks;
}

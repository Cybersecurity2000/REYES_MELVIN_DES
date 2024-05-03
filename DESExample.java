package com.mycompany.desexample;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;
import java.util.Base64;

public class DESExample {

    public static byte[] generateDESKey() throws Exception {
        SecureRandom secureRandom = new SecureRandom();
        byte[] key = new byte[8];
        secureRandom.nextBytes(key);
        return key;
    }

    public static byte[] encryptMessage(String message, byte[] key) throws Exception {
        Cipher cipher = Cipher.getInstance("DES/ECB/PKCS5Padding");
        SecretKeySpec secretKey = new SecretKeySpec(key, "DES");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        byte[] encrypted = cipher.doFinal(message.getBytes());
        return encrypted;
    }

    public static String decryptMessage(byte[] ciphertext, byte[] key) throws Exception {
        Cipher cipher = Cipher.getInstance("DES/ECB/PKCS5Padding");
        SecretKeySpec secretKey = new SecretKeySpec(key, "DES");
        cipher.init(Cipher.DECRYPT_MODE, secretKey);
        byte[] decrypted = cipher.doFinal(ciphertext);
        return new String(decrypted);
    }

    public static void main(String[] args) throws Exception {
        byte[] key = generateDESKey();
        String message = "Hello, this is a secret message.";

        byte[] encrypted = encryptMessage(message, key);
        System.out.println("Encrypted: " + Base64.getEncoder().encodeToString(encrypted));

        String decrypted = decryptMessage(encrypted, key);
        System.out.println("Decrypted: " + decrypted);
    }
}

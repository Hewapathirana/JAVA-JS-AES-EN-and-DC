package com.company;

import sun.misc.BASE64Decoder;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;

public class Main {
     //code for react or react native


/*
   //stackoverflow link ==https://stackoverflow.com/questions/36733132/react-native-aes-encryption-matching-java-decryption-algorithm
pre coding: npm install crypto-js

      import CryptoJS from 'crypto-js' ;
      encryptFun() {
        var data = "123456";
        var key  = CryptoJS.enc.Latin1.parse('1234567812345678');
        var iv   = CryptoJS.enc.Latin1.parse('1234567812345678');
        var encrypted = CryptoJS.AES.encrypt(
                data,
                key,
                {iv:iv,mode:CryptoJS.mode.CBC,padding:CryptoJS.pad.ZeroPadding
    });
        console.log('encrypted: ' + encrypted) ;
        var decrypted = CryptoJS.AES.decrypt(encrypted,key,{iv:iv,padding:CryptoJS.pad.ZeroPadding});
        console.log('decrypted: '+decrypted.toString(CryptoJS.enc.Utf8));
    }*/

   //this method used inside the decrypt method
    public static String encrypt() throws Exception {
        try {
            String data = "123456";
            String key = "1234567812345678";
            String iv = "1234567812345678";

            Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding");
            int blockSize = cipher.getBlockSize();

            byte[] dataBytes = data.getBytes();
            int plaintextLength = dataBytes.length;
            if (plaintextLength % blockSize != 0) {
                plaintextLength = plaintextLength + (blockSize - (plaintextLength % blockSize));
            }

            byte[] plaintext = new byte[plaintextLength];
            System.arraycopy(dataBytes, 0, plaintext, 0, dataBytes.length);

            SecretKeySpec keyspec = new SecretKeySpec(key.getBytes(), "AES");
            IvParameterSpec ivspec = new IvParameterSpec(iv.getBytes());

            cipher.init(Cipher.ENCRYPT_MODE, keyspec, ivspec);
            byte[] encrypted = cipher.doFinal(plaintext);

            return new sun.misc.BASE64Encoder().encode(encrypted);

        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    public static String desEncrypt() throws Exception {
        //String encrypted = encrypt() ;
        try
        {
            String data = "aK7+UX24ttBgfTnAndz9aQ==" ;
            String key = "1234567812345678";
            String iv = "1234567812345678";

            Base64.Decoder decoder = Base64.getDecoder();
            byte[] encrypted1 = decoder.decode(data);

            Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding");
            SecretKeySpec keyspec = new SecretKeySpec(key.getBytes(), "AES");
            IvParameterSpec ivspec = new IvParameterSpec(iv.getBytes());

            cipher.init(Cipher.DECRYPT_MODE, keyspec, ivspec);

            byte[] original = cipher.doFinal(encrypted1);

            String originalStringx = new String(original);
            System.out.println("original = "+originalStringx.trim()); //.equals("123456")
            return originalStringx;
        }
        catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }


    public static void main(String[] args) {

       /* final String secretKey = "tyuu";

        String originalString = "howtodoinjava.com";
        String encryptedString = AES.encrypt(originalString, secretKey) ;
        String decryptedString = AES.decrypt(encryptedString, secretKey) ;

        System.out.println(originalString);
        System.out.println(encryptedString);
        System.out.println(decryptedString);*/




       //below part is for above static methods
        try {
            desEncrypt();
        } catch (Exception e) {
            e.printStackTrace();
        }


    }
}

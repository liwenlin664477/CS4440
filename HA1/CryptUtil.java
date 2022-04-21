package HA1;


import java.io.*;
import java.util.Random;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;



public class CryptUtil {

    public static byte[] createSha1(File file) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-1");
        InputStream fis = new FileInputStream(file);
        int n = 0;
        byte[] buffer = new byte[8192];
        while (n != -1) {
            n = fis.read(buffer);
            if (n > 0) {
                digest.update(buffer, 0, n);
            }
        }
        fis.close();
        return digest.digest();
    }

    public static boolean compareSha1(String filename1, String filename2) throws Exception {
        File file1 = new File(filename1);
        File file2 = new File(filename2);
        byte[] fsha1 = CryptUtil.createSha1(file1);
        byte[] fsha2 = CryptUtil.createSha1(file2);
        return Arrays.equals(fsha1, fsha2);
    }

    public static double getShannonEntropy(String s) {
        int n = 0;
        Map<Character, Integer> occ = new HashMap<>();

        for (int c_ = 0; c_ < s.length(); ++c_) {
            char cx = s.charAt(c_);
            if (occ.containsKey(cx)) {
                occ.put(cx, occ.get(cx) + 1);
            } else {
                occ.put(cx, 1);
            }
            ++n;
        }

        double e = 0.0;
        for (Map.Entry<Character, Integer> entry : occ.entrySet()) {
            char cx = entry.getKey();
            double p = (double) entry.getValue() / n;
            e += p * log2(p);
        }
        return -e;
    }

    public static double getShannonEntropy(byte[] data) {

        if (data == null || data.length == 0) {
            return 0.0;
        }

        int n = 0;
        Map<Byte, Integer> occ = new HashMap<>();

        for (int c_ = 0; c_ < data.length; ++c_) {
            byte cx = data[c_];
            if (occ.containsKey(cx)) {
                occ.put(cx, occ.get(cx) + 1);
            } else {
                occ.put(cx, 1);
            }
            ++n;
        }

        double e = 0.0;
        for (Map.Entry<Byte, Integer> entry : occ.entrySet()) {
            byte cx = entry.getKey();
            double p = (double) entry.getValue() / n;
            e += p * log2(p);
        }
        return -e;
    }

    public static double getFileShannonEntropy(String filePath) {
        try {
            byte[] content;
            content = Files.readAllBytes(Paths.get(filePath));
            return CryptUtil.getShannonEntropy(content);
        } catch (IOException e) {
            e.printStackTrace();
            return -1;
        }

    }

    private static double log2(double a) {
        return Math.log(a) / Math.log(2);
    }

    public static void doCopy(InputStream is, OutputStream os) throws IOException {
        byte[] bytes = new byte[64];
        int numBytes;
        while ((numBytes = is.read(bytes)) != -1) {
            os.write(bytes, 0, numBytes);
        }
        os.flush();
        os.close();
        is.close();
    }

    public static Byte randomKey() {
        int leftLimit = 48; // numeral '0'
        int rightLimit = 122; // letter 'z'
        int targetStringLength = 8;
        Random random = new Random();
        String generatedString = random.ints(leftLimit, rightLimit + 1)
                .filter(i -> (i <= 57 || i >= 65) && (i <= 90 || i >= 97))
                .limit(targetStringLength)
                .collect(StringBuilder::new, StringBuilder::appendCodePoint, StringBuilder::append)
                .toString();
        return generatedString.getBytes()[0];
    }

    /**
     * Encryption (Bytes)
     *
     * @param data
     * @param key
     * @return encrypted bytes
     */
    public static byte[] cs4440Encrypt(byte[] data, Byte key){
        if (data == null || data.length == 0 || key == null || key.toString().getBytes().length == 0) {
            return data;
        }
        byte[]keyBytes = key.toString().getBytes();
        byte[] result = new byte[data.length];

        for (int i = 0; i < data.length; i++) {
            result[i] = (byte) (data[i] ^ keyBytes[i % keyBytes.length]^ (i & 0xFF));
        }

        return result;

    }
    

    /**
     * Encryption (file)
     *
     * @param plainfilepath
     * @param cipherfilepath
     * @param key
     */
    public static int encryptDoc(String plainfilepath, String cipherfilepath, Byte key) {
    	   try {
    		   InputStream plainfile = new FileInputStream(plainfilepath); 		   
    		   OutputStream cipherfile = new FileOutputStream(cipherfilepath);
               byte[] plain;
               ByteArrayOutputStream bout = new ByteArrayOutputStream();
               plain = plainfile.readAllBytes();
               int noBlocks = plain.length / 8;
               if (plain.length % 8 == 0) {
            	   int length = 0;
            	   while(length < plain.length) {
            		   byte[] tempBlock = new byte[8];
            		   for(int i = 0; i < tempBlock.length; i++) {
            			   tempBlock[i] = plain[length + i];
            		   }
            		   byte[] buf = cs4440Encrypt(tempBlock, key);
           		       bout.write(buf);
            		   length = length + 8; 
            	   }         	   
               }else {
            	   int length = 0;
            	   int restByte = plain.length - noBlocks * 8;
            	   while(length < plain.length - restByte) {
            		   byte[] tempBlock = new byte[8];
            		   for(int i = 0; i < tempBlock.length; i++) {
            			   tempBlock[i] = plain[length + i];
            		   }
            		   byte[] buf = cs4440Encrypt(tempBlock, key);
           		       bout.write(buf);
            		   length = length + 8; 
            	   } 
            	   byte[] newByte = new byte[8];
            	   for(int i = 0; i < 8; i++) {
            		   newByte[i] = -1;
            	   }

       		       for(int i = 0; i < restByte; i++) {
       		    	newByte[i] = plain[noBlocks * 8 + i];
       		       }
       		       byte[] buf = cs4440Encrypt(newByte, key);
       		       bout.write(buf);            	   
               }
               cipherfile.write(bout.toByteArray());
               return 0;
               
           } catch (IOException e) {
               e.printStackTrace();
               return -1;
           }

    }
    


    /**
     * decryption
     *
     * @param data
     * @param key
     * @return decrypted content
     */

    public static byte[] cs4440Decrypt(byte[] data, Byte key){
        return cs4440Encrypt(data,key);
    }

    /**
     * Decryption (file)
     * @param plainfilepath
     * @param cipherfilepath
     * @param key
     */
    public static int decryptDoc(String cipherfilepath, String plainfilepath, Byte key) {
 	   try {
 		   InputStream cipherfile = new FileInputStream(cipherfilepath);
 		   OutputStream plainfile = new FileOutputStream(plainfilepath);
           byte[] cipher;
           ByteArrayOutputStream bout = new ByteArrayOutputStream();
           cipher = cipherfile.readAllBytes();
           int noBlocks = cipher.length / 8;
           if (cipher.length % 8 == 0) {
        	   int length = 0;
        	   while(length < cipher.length) {
        		   if(length == cipher.length - 8) {
        			  int count = 0;
        			  for(int i = 0; i < 8; i++) {
        				  if(cipher[length + i] > 0) {
        					  count++;
        				  }
        			  }
        			  byte[] tempBlock = new byte[count];
        			  for(int j = 0; j < tempBlock.length; j++) {
        				  tempBlock[j] = cipher[length + j];
        			  }
        			  byte[] buf = cs4440Encrypt(tempBlock, key);
          		      bout.write(buf);
          		    length = length + 8; 
        		   }
        		   else
        		   {        		   
        		   byte[] tempBlock = new byte[8];
        		   for(int i = 0; i < tempBlock.length; i++) {
        			   tempBlock[i] = cipher[length + i];
        		   }
        		   byte[] buf = cs4440Encrypt(tempBlock, key);
       		       bout.write(buf);
        		   length = length + 8; 
        		   }
        	   }           	   
           }
           plainfile.write(bout.toByteArray());
           return 0;
           
       } catch (IOException e) {
           e.printStackTrace();
           return -1;
       }

    }
    

    public static void main(String[] args) {

        String targetFilepath = "";
        String encFilepath = "";
        String decFilepath = "";
        System.out.println(args[0].toString());
        if (args.length == 3) {
            try {
                File file1 = new File(args[0].toString());
                if (file1.exists() && !file1.isDirectory()) {
                    targetFilepath = args[0].toString();
                } else {
                    System.out.println("File does not exist!");
                    System.exit(1);
                }

                encFilepath = args[1].toString();
                decFilepath = args[2].toString();
            } catch (Exception e) {
                e.printStackTrace();
                System.exit(1);
            }
        } else {
            // targetFilepath = "cs4440-a1-testcase1.html";
            System.out.println("Usage: java CryptoUtil file_to_be_encrypted encrypted_file decrypted_file");
            System.exit(1);
        }

        Byte key = randomKey();
        String src = "ABCDEFGH";
        System.out.println("[*] Now testing plain sampleï¼š " + src);
        try {
            byte[] encrypted = CryptUtil.cs4440Encrypt(src.getBytes(), key);
            StringBuilder encsb = new StringBuilder();
            for (byte b : encrypted) {
                encsb.append(String.format("%02X ", b));
            }
            System.out.println("[*] The  encrypted sample  [Byte Format]ï¼š " + encsb);
            double entropyStr = CryptUtil.getShannonEntropy(encrypted.toString());
            System.out.printf("[*] Shannon entropy of the text sample (to String): %.12f%n", entropyStr);
            double entropyBytes = CryptUtil.getShannonEntropy(encrypted);
            System.out.printf("[*] Shannon entropy of encrypted message (Bytes): %.12f%n", entropyBytes);

            byte[] decrypted = CryptUtil.cs4440Decrypt(encrypted, key);
	    if (Arrays.equals(decrypted, src.getBytes())){
                System.out.println("[+] It works!  decrypted ï¼š " + decrypted);
            } else {
                System.out.println("Decrypted message does not match!");
            }

            // File Encryption
            System.out.printf("[*] Encrypting target file: %s \n", targetFilepath);
            System.out.printf("[*] The encrypted file will be: %s \n", encFilepath);
            System.out.printf("[*] The decrypted file will be: %s \n", decFilepath);

            CryptUtil.encryptDoc(targetFilepath, encFilepath, key);
//            System.out.printf("here");
            CryptUtil.decryptDoc(encFilepath, decFilepath, key);

            System.out.printf("[+] [File] Entropy of the original file: %s \n",
                    CryptUtil.getFileShannonEntropy(targetFilepath));
            System.out.printf("[+] [File] Entropy of encrypted file: %s \n",
                    CryptUtil.getFileShannonEntropy(encFilepath));

            if (CryptUtil.compareSha1(targetFilepath, decFilepath)) {
                System.out.println("[+] The decrypted file is the same as the source file");
            } else {
                System.out.println("[+] The decrypted file is different from the source file.");
                System.out.println("[+] $ cat '<decrypted file>' to to check the differences");
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

}

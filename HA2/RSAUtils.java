package HA2;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayOutputStream;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Random;

/**
 * RSA
 * Generate a key pair (public and private key)
 * Base64 encryption and decryption of encrypted content and signed content
 * (conducive to transmission under HTTP protocol)
 */
public class RSAUtils {
    /**
     * NAME
     */
    private static final String ALGORITHM = "RSA";
    /**
     * SIGNATURE_ALGORITHM MD5withRSA or SHA1WithRSA
     */
    public static final String SIGNATURE_ALGORITHM = "MD5withRSA";
    /**
     * 1024 bit
     * The maximum length of encrypted plaintext = key length - 11 (bytes)
     */
    private static final int KEY_SIZE = 1024;
    /**
     * RSA maximum encrypted plaintext size
     */
    private static final int MAX_ENCRYPT_BLOCK = 117;

    /**
     * RSA maximum decrypted ciphertext size
     */
    private static final int MAX_DECRYPT_BLOCK = 128;

    private RSAUtils() {
    }

    /**
     *
     * @return key pair
     */
    public static KeyPair getKeyPair() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance(ALGORITHM);
        generator.initialize(KEY_SIZE);
        return generator.generateKeyPair();
    }

    /**
     * Private key string to PrivateKey instance
     *
     * @param privateKey String
     * @return
     */
    public static PrivateKey getPrivateKey(String privateKey) throws Exception {
        KeyFactory keyFactory = KeyFactory.getInstance(ALGORITHM);
        byte[] decodedKey = Base64.getDecoder().decode(privateKey.getBytes("UTF-8"));
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(decodedKey);
        return keyFactory.generatePrivate(keySpec);
    }

    /**
     * Convert public key string to PublicKey instance
     *
     * @param publicKey String
     * @return
     */
    public static PublicKey getPublicKey(String publicKey) throws Exception {
        KeyFactory keyFactory = KeyFactory.getInstance(ALGORITHM);
        byte[] decodedKey = Base64.getDecoder().decode(publicKey.getBytes("UTF-8"));
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(decodedKey);
        return keyFactory.generatePublic(keySpec);
    }

    /**
     *
     * @param data      String
     * @param publicKey
     * @return
     */
    public static String encryptByPublicKey(String data, PublicKey publicKey) {
        try (
                ByteArrayOutputStream out = new ByteArrayOutputStream();) {
            Cipher cipher = Cipher.getInstance(ALGORITHM);
            cipher.init(Cipher.ENCRYPT_MODE, publicKey);
            int inputLen = data.getBytes("UTF-8").length;
            int offset = 0;
            byte[] cache;
            int i = 0;
            // encryption of data
            while (inputLen - offset > 0) {
                if (inputLen - offset > MAX_ENCRYPT_BLOCK) {
                    cache = cipher.doFinal(data.getBytes("UTF-8"), offset, MAX_ENCRYPT_BLOCK);
                } else {
                    cache = cipher.doFinal(data.getBytes("UTF-8"), offset, inputLen - offset);
                }
                out.write(cache, 0, cache.length);
                i++;
                offset = i * MAX_ENCRYPT_BLOCK;
            }
            byte[] encryptedData = out.toByteArray();
            // The encrypted content is encoded and encrypted using Base64, and converted
            // into a string using UTF-8 as the standard
            // return new String(Base64.encodeBase64String(encryptedData));
            return new String(Base64.getEncoder().encode(encryptedData), "UTF-8");
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    /**
     *
     * @param data       String
     * @param privateKey
     * @return
     */
    public static String decryptByPrivateKey(String data, PrivateKey privateKey) {
        try (
                ByteArrayOutputStream out = new ByteArrayOutputStream();) {
            Cipher cipher = Cipher.getInstance(ALGORITHM);
            cipher.init(Cipher.DECRYPT_MODE, privateKey);

            // Base64 encoding and decryption of decrypted data
            byte[] dataBytes = Base64.getDecoder().decode(data.getBytes("UTF-8"));
            int inputLen = dataBytes.length;
            int offset = 0;
            byte[] cache;
            int i = 0;
            while (inputLen - offset > 0) {
                if (inputLen - offset > MAX_DECRYPT_BLOCK) {
                    cache = cipher.doFinal(dataBytes, offset, MAX_DECRYPT_BLOCK);
                } else {
                    cache = cipher.doFinal(dataBytes, offset, inputLen - offset);
                }
                out.write(cache, 0, cache.length);
                i++;
                offset = i * MAX_DECRYPT_BLOCK;
            }
            byte[] decryptedData = out.toByteArray();
            return new String(decryptedData, "UTF-8");
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    /**
     * Sign
     *
     * @param data       String
     * @param privateKey
     * @return
     */
    public static String sign(String data, PrivateKey privateKey) throws Exception {
        byte[] keyBytes = privateKey.getEncoded();
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance(ALGORITHM);
        PrivateKey key = keyFactory.generatePrivate(keySpec);
        Signature signature = Signature.getInstance(SIGNATURE_ALGORITHM);
        signature.initSign(key);
        signature.update(data.getBytes());
        return new String(Base64.getEncoder().encode(signature.sign()));
    }

    /**
     *
     * @param srcData   Original string
     * @param publicKey
     * @param sign
     * @return bool
     */
    public static boolean verify(String srcData, PublicKey publicKey, String sign) throws Exception {
        byte[] keyBytes = publicKey.getEncoded();
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance(ALGORITHM);
        PublicKey key = keyFactory.generatePublic(keySpec);
        Signature signature = Signature.getInstance(SIGNATURE_ALGORITHM);
        signature.initVerify(key);
        signature.update(srcData.getBytes());
        return signature.verify(Base64.getDecoder().decode(sign.getBytes()));
    }

    public static String aesEncrypt(String sSrc, String sKey) throws Exception {
        if (sKey == null) {
            System.out.print("Key is null");
            return null;
        }
        // Key.length
        if (sKey.length() != 16) {
            System.out.print("Key's length is not 16");
            return null;
        }
        byte[] raw = sKey.getBytes();
        SecretKeySpec skeySpec = new SecretKeySpec(raw, "AES");
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        IvParameterSpec iv = new IvParameterSpec("0102030405060708".getBytes());
        cipher.init(Cipher.ENCRYPT_MODE, skeySpec, iv);
        byte[] encrypted = cipher.doFinal(sSrc.getBytes());

        return byte2hex(encrypted).toLowerCase();
    }

    // Dec
    public static String aesDecrypt(String sSrc, String sKey) throws Exception {
        try {
            // is key correct?
            if (sKey == null) {
                System.out.print("Key null");
                return null;
            }
            // key 16 bit
            if (sKey.length() != 16) {
                System.out.print("Key.length != 16");
                return null;
            }
            byte[] raw = sKey.getBytes("ASCII");
            SecretKeySpec skeySpec = new SecretKeySpec(raw, "AES");
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            IvParameterSpec iv = new IvParameterSpec("0102030405060708"
                    .getBytes());
            cipher.init(Cipher.DECRYPT_MODE, skeySpec, iv);
            byte[] encrypted1 = hex2byte(sSrc);
            try {
                byte[] original = cipher.doFinal(encrypted1);
                String originalString = new String(original);
                return originalString;
            } catch (Exception e) {
                System.out.println(e.toString());
                return null;
            }
        } catch (Exception ex) {
            System.out.println(ex.toString());
            return null;
        }
    }

    public static byte[] hex2byte(String strhex) {
        if (strhex == null) {
            return null;
        }
        int l = strhex.length();
        if (l % 2 == 1) {
            return null;
        }
        byte[] b = new byte[l / 2];
        for (int i = 0; i != l / 2; i++) {
            b[i] = (byte) Integer.parseInt(strhex.substring(i * 2, i * 2 + 2),
                    16);
        }
        return b;
    }

    public static String byte2hex(byte[] b) {
        String hs = "";
        String stmp = "";
        for (int n = 0; n < b.length; n++) {
            stmp = (java.lang.Integer.toHexString(b[n] & 0XFF));
            if (stmp.length() == 1) {
                hs = hs + "0" + stmp;
            } else {
                hs = hs + stmp;
            }
        }
        return hs.toUpperCase();
    }

    public static String randomAlphabeticString() {
        int leftLimit = 97; // letter 'a'
        int rightLimit = 122; // letter 'z'
        int targetStringLength = 10;
        Random random = new Random();

        String generatedString = random.ints(leftLimit, rightLimit + 1)
                .limit(targetStringLength)
                .collect(StringBuilder::new, StringBuilder::appendCodePoint, StringBuilder::append)
                .toString();

        return generatedString;
    }

    public static void main(String[] args) {

        try {
            // AES
            String cKey = "1234567890123456";
            String cSrc = "This is a test message...";
            System.out.println("==== AES ====");
            System.out.println(cSrc);
            // enc
            long lStart = System.currentTimeMillis();
            String enString = RSAUtils.aesEncrypt(cSrc, cKey);
            System.out.println("Encrypted：" + enString);

            long lUseTime = System.currentTimeMillis() - lStart;
            System.out.println("Encryption takes: " + lUseTime + "ms");
            // dec
            lStart = System.currentTimeMillis();
            String DeString = RSAUtils.aesDecrypt(enString, cKey);
            System.out.println("Decrypted string: " + DeString);
            lUseTime = System.currentTimeMillis() - lStart;
            System.out.println("Encryption takes :" + lUseTime + "ms");

            // RSA
            // Generate Key pair
            System.out.println("==== RSA ====");
            KeyPair keyPair = getKeyPair();
            String privateKey = new String(Base64.getEncoder().encode(keyPair.getPrivate().getEncoded()), "UTF-8");
            String publicKey = new String(Base64.getEncoder().encode(keyPair.getPublic().getEncoded()), "UTF-8");
            System.out.println("Private key: " + privateKey);
            System.out.println("Private key's length: " + privateKey.length());
            System.out.println("Public key:" + publicKey);
            System.out.println("Public key's length:" + publicKey.length());
            // RSA enc
            String data = "\nThe signature algorithm can be NIST standard DSAThis Standard specifies a suite of algorithms that can be used to generate a digital signature.\n";
            String encryptData = encryptByPublicKey(data, getPublicKey(publicKey));
            System.out.println("Encrypted content: " + encryptData);
            // RSA dec
            String decryptData = decryptByPrivateKey(encryptData, getPrivateKey(privateKey));
            System.out.println("Decrypted content: " + decryptData);

            // RSA sign
            String sign = sign(data, getPrivateKey(privateKey));
            System.out.println("Signature: " + sign);
            System.out.println("Signature's length: " + sign.length());
            // RSA verify
            boolean result = verify(data, getPublicKey(publicKey), sign);
            System.out.print("\nVerification result 1 : " + result);

            boolean result2 = verify(
                    "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCOUi2G/d0ne690bXruDoTMbweqWo/2ZSvvj9DdygSY7wY8JzSQqbJyruD0TyveeLTVfHdi8HuZ8QI+jYshGx52DlbUZng4u5r/Vu2HonSxMivcu5WJWHEwBURNEnMJvnWHTm4Gx7AlI1uirym+uqq+TToAXdlTc6ctj1f7lMlW5QIDAQAB",
                    getPublicKey(
                            "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCOUi2G/d0ne690bXruDoTMbweqWo/2ZSvvj9DdygSY7wY8JzSQqbJyruD0TyveeLTVfHdi8HuZ8QI+jYshGx52DlbUZng4u5r/Vu2HonSxMivcu5WJWHEwBURNEnMJvnWHTm4Gx7AlI1uirym+uqq+TToAXdlTc6ctj1f7lMlW5QIDAQAB"),
                    "c2B9r9HMTtmkmiTu+82m+JaalJTlHpPlxgoa2bGKaI/bRFuMq8bdF7vq2k0rprjoBBxoafpLqh/wrAMGhvA1LKizikFy9yaripiWNZZ/Yh+qm5nkUyOiysQhCcyvYxOGYtqw+nv9grZAZ1NvH+ap/rsMxiUoYyY5K/bS6vGPDEw=");
            System.out.print("\nVerification result 22: " + result2);
        } catch (Exception e) {
            e.printStackTrace();
            System.out.print("Error when encrypting/decrypting");
        }
    }
}
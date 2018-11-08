package rsautils;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class AESUtil {
    private AESUtil() {
    }


    private static final String UTF8 = "utf-8";


    //产生密钥
    public static String initAESkey() throws Exception {

        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(256);
        SecretKey secretKey = keyGen.generateKey();
        return Base64Util.encryptBASE(secretKey.getEncoded());
    }

    //加密
    public static String encrypt(String data, String key) throws Exception {
        SecretKey secretKey = new SecretKeySpec(Base64Util.decryptBASE(key), "AES");
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        byte[] encrypted = cipher.doFinal(data.getBytes(UTF8));
        return Base64Util.encryptBASE(encrypted);
    }

    //解密
    public static String decrypt(String data, String key) throws Exception {
        SecretKey secretKey = new SecretKeySpec(Base64Util.decryptBASE(key), "AES");
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.DECRYPT_MODE, secretKey);
        byte[] encrypted = Base64Util.decryptBASE(data);
        byte[] original = cipher.doFinal(encrypted);
        return new String(original, UTF8);
    }
    // ################## AES自动生成密钥 end ######################
}

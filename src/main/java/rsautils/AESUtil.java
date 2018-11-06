package rsautils;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class AESUtil {
    private AESUtil() {
    }

    // ################## AES自定义密钥 start ######################
    private static final String AESKEY = "0123456789abcdef"; //AES加密参数（必须16位）
    private static final String AES_IVPARAMETER = "0123456789abcdef"; //AES加密向量（必须16位）
    private static final String UTF8 = "utf-8";

    private static final String AES_ALGORITHM = "AES/GCM/NoPadding";

    // AES加密
    public static String encrypt(String sSrc) {
        try {
            Cipher cipher = Cipher.getInstance(AES_ALGORITHM);
            byte[] raw = AESKEY.getBytes("ASCII");
            SecretKeySpec skeySpec = new SecretKeySpec(raw, "AES");
            IvParameterSpec iv = new IvParameterSpec(AES_IVPARAMETER.getBytes());
            cipher.init(Cipher.ENCRYPT_MODE, skeySpec, iv);
            byte[] encrypted = cipher.doFinal(sSrc.getBytes(UTF8));
            return Base64Util.encryptBASE(encrypted);
        } catch (Exception ex) {
            return null;
        }
    }

    // AES解密
    public static String decrypt(String sSrc) {
        try {
            byte[] raw = AESKEY.getBytes("ASCII");
            SecretKeySpec skeySpec = new SecretKeySpec(raw, "AES");
            Cipher cipher = Cipher.getInstance(AES_ALGORITHM);
            IvParameterSpec iv = new IvParameterSpec(AES_IVPARAMETER.getBytes());
            cipher.init(Cipher.DECRYPT_MODE, skeySpec, iv);
            byte[] encrypted = Base64Util.decryptBASE(sSrc);
            byte[] original = cipher.doFinal(encrypted);
            return new String(original, UTF8);
        } catch (Exception ex) {
            return null;
        }
    }
    // ################## AES自定义密钥 end ######################


    // ################## AES自动生成密钥 start ######################
    //产生密钥
    public static String initAESkey() throws Exception {

        KeyGenerator keyGen = KeyGenerator.getInstance("AES");

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

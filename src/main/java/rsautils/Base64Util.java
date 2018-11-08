package rsautils;

import org.apache.commons.codec.binary.Base64;

public class Base64Util {
    private Base64Util(){}


    public static String encryptBASE(byte[] key){
        return Base64.encodeBase64String(key);
    }

    public static byte[] decryptBASE(String key){
        return Base64.decodeBase64(key);
    }
}

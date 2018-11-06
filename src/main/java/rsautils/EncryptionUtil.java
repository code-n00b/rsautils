package rsautils;

import com.alibaba.fastjson.JSONObject;

public final class EncryptionUtil {

    private static final String GEN_AES_ERROR = "生成AESkey错误{}";
    private static final String VERIFY_SIGN_ERROR = "私钥验证签名错误";
    private static final String DES_CRY_ERROR = "解密过程中发生错误{}";

    private EncryptionUtil() {
        // No-op; won't be called
    }

    /**
     * 第一次初始化AESkey较慢
     */
    static {
        try {
            AESUtil.initAESkey();
        } catch (Exception e) {
        }
    }

    /**
     * 使用keystore中的私钥对数据进行签名，返回一个含有datacontent,sign,aeskey,appno的HashMap
     *
     * @return 返回data被随机生成的AES密钥加密后datacontent，取datacontent的SHA1值并使用私钥签名得到sign，随机生成的aes密钥使用公钥家阿米后得到aeskey,传入的appno
     * @throws Exception
     */
    public static JSONObject encryptData(String data, String keyStorePath, String password,
                                     String alias,String cerPath) throws Exception {
        // 生产一个随机key用于加密报文
        String AESKey = AESUtil.initAESkey();
        String encryptedData = AESUtil.encrypt(data, AESKey);
        String encryptedAESKey = RSAUtil.encryptByPublicKey(AESKey, cerPath);
        String SHA1EncryptedData = SHAUtil.getSHA1Code(encryptedData);
        String sign = RSAUtil.encryptByPrivateKey(SHA1EncryptedData, keyStorePath, alias, password);

        JSONObject dataJson = new JSONObject();
        dataJson.put("data", encryptedData);
        dataJson.put("sign", sign);
        dataJson.put("aeskey", encryptedAESKey);
        return dataJson;
    }

    /**
     * 使用keystore文件中的私钥对密文进行解密，返回data的解密结果，若解密过程出现异常，则返回ERROR开头的字段
     *
     * @param data
     * @param sign
     * @param keyStorePath
     * @param alias
     * @param password
     * @return
     * @throws Exception
     */
    public static String decryptData(String data, String sign, String AESKey, String keyStorePath, String alias,
                                     String password, String cerPath) throws Exception {
        String ret = "";
        try {
            String SHA1EncryptedData = SHAUtil.getSHA1Code(data);
            String decryptedSign = RSAUtil.decryptByPublicKey(sign, cerPath);
            // 验证sign
            if (!SHA1EncryptedData.equals(decryptedSign)) {
                throw new Exception(VERIFY_SIGN_ERROR);
            }
            AESKey = RSAUtil.decryptByPrivateKey(AESKey, keyStorePath, alias, password);
            String dataContent = AESUtil.decrypt(data, AESKey);
            ret = dataContent;
            return ret;
        } catch (Exception e) {
            throw e;
        }

    }



}
package rsautils;

import javax.crypto.Cipher;
import java.io.FileInputStream;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Date;

public class RSAUtil {
    private RSAUtil(){}
    
    private static final String UTF8="utf-8";


    public static final String KEY_STORE = "JKS";
    public static final String X509 = "X.509";

    //由keystore获得私钥
    public static PrivateKey getPrivateKey(String keyStorePath, String alias, String password) throws Exception {
        KeyStore ks = getKeyStore(keyStorePath, password);
        return (PrivateKey) ks.getKey(alias, password.toCharArray());
    }

	//由Certificate获得公钥 
    public static PublicKey getPublicKey(String certificatePath) throws Exception {
        Certificate certificate = getCertificate(certificatePath);
        return  certificate.getPublicKey();

    }

	//获得Certificate
    public static Certificate getCertificate(String certificatePath) throws Exception {
        CertificateFactory certificateFactory = CertificateFactory.getInstance(X509);
        try (FileInputStream in = new FileInputStream(certificatePath);){
            return certificateFactory.generateCertificate(in);
        }catch (Exception e){
            throw e;
        }


    }

    //获得Certificate 
    public static Certificate getCertificate(String keyStorePath, String alias, String password) throws Exception {
        KeyStore ks = getKeyStore(keyStorePath, password);
        return ks.getCertificate(alias);
    }

    //获得KeyStore
    public static KeyStore getKeyStore(String keyStorePath, String password) throws Exception {
        
        KeyStore ks = KeyStore.getInstance(KEY_STORE);
        try(FileInputStream is = new FileInputStream(keyStorePath)){
            ks.load(is, password.toCharArray());
            return ks;
        }catch (Exception e){
            throw e;
        }


    }

    //私钥加密 
    public static String encryptByPrivateKey(String data, String keyStorePath, String alias, String password) throws Exception {
    	
    	PrivateKey privateKey = getPrivateKey(keyStorePath, alias, password);
		
          
        Cipher cipher = Cipher.getInstance(privateKey.getAlgorithm());
        cipher.init(Cipher.ENCRYPT_MODE, privateKey);
 
        byte[] encrypted = cipher.doFinal(data.getBytes(UTF8));
        
        return Base64Util.encryptBASE(encrypted);
    }

    //私钥解密
    public static String decryptByPrivateKey(String data, String keyStorePath, String alias, String password) throws Exception {
        PrivateKey privateKey = getPrivateKey(keyStorePath, alias, password);
        Cipher cipher = Cipher.getInstance(privateKey.getAlgorithm());
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
    	byte[] encrypted = Base64Util.decryptBASE(data);
    	byte[] original = cipher.doFinal(encrypted);
    	return new String(original, UTF8);
    }

    //公钥加密
    public static String encryptByPublicKey(String data, String certificatePath) throws Exception {
        PublicKey publicKey = getPublicKey(certificatePath);
        Cipher cipher = Cipher.getInstance(publicKey.getAlgorithm());
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] encrypted = cipher.doFinal(data.getBytes(UTF8));
        return Base64Util.encryptBASE(encrypted);
    }

    //公钥解密
    public static String decryptByPublicKey(String data, String certificatePath) throws Exception { 
        PublicKey publicKey = getPublicKey(certificatePath);
        Cipher cipher = Cipher.getInstance(publicKey.getAlgorithm());
        cipher.init(Cipher.DECRYPT_MODE, publicKey);
    	byte[] encrypted = Base64Util.decryptBASE(data);
    	byte[] original = cipher.doFinal(encrypted);
    	return new String(original, UTF8);
    }

   //签名 
    public static String sign(String sign, String keyStorePath, String alias, String password) throws Exception {
        X509Certificate x509Certificate = (X509Certificate)getCertificate(keyStorePath, alias, password);
        KeyStore ks = getKeyStore(keyStorePath, password);
        PrivateKey privateKey = (PrivateKey) ks.getKey(alias, password.toCharArray());
        Signature signature = Signature.getInstance(x509Certificate.getSigAlgName());
        signature.initSign(privateKey);
        signature.update(sign.getBytes(UTF8));
        return Base64Util.encryptBASE(signature.sign());
    }

    //验证签名
    public static boolean verify(String data, String sign, String certificatePath) throws Exception {
        X509Certificate x509Certificate = (X509Certificate) getCertificate(certificatePath);
        PublicKey publicKey = x509Certificate.getPublicKey();
        Signature signature = Signature.getInstance(x509Certificate.getSigAlgName());
        signature.initVerify(publicKey);
        signature.update(data.getBytes(UTF8));
        return signature.verify(Base64Util.decryptBASE(sign));
    }
    
    //验证证书是否过期（与指定日期对比）
    public static boolean verifyCertificate(Date date, String certificatePath) {
        boolean status = true;
        try {
            Certificate certificate = getCertificate(certificatePath);
            status = verifyCertificate(date, certificate);
        } catch (Exception e) {
            status = false;
        }
        return status;
    }
    
    //验证证书是否过期（与系统当前日期对比）
    public static boolean verifyCertificate(String certificatePath) {
        return verifyCertificate(new Date(), certificatePath);
    }

    //验证证书是否过期（证书类型参数）
    public static boolean verifyCertificate(Date date, Certificate certificate) {
        boolean status = true;
        try {
            X509Certificate x509Certificate = (X509Certificate) certificate;
            x509Certificate.checkValidity(date);
        } catch (Exception e) {
            status = false;
        }
        return status;
    }

    //验证证书是否过期（需要密码，与指定时间对比）
    public static boolean verifyCertificate(Date date, String keyStorePath, String alias, String password) {
        boolean status = true;  
        try {  
            Certificate certificate = getCertificate(keyStorePath, alias, password);
            status = verifyCertificate(date, certificate);
        } catch (Exception e) {
            status = false;
        }
        return status;
    }
  
    //验证证书是否过期（需要密码，与系统当前日期对比）
    public static boolean verifyCertificate(String keyStorePath, String alias, String password) {
        return verifyCertificate(new Date(), keyStorePath, alias, password);
    }
    //##################### RSA 使用证书方式 结束 ##############################
}

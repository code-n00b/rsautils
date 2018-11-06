package rsautils;

import java.security.MessageDigest;

public class SHAUtil {

	private SHAUtil(){}

	/**
	 * SHA签名
	 * @param inputStr
	 * @return
	 * @throws Exception
	 */
	public static String getSHA1Code(String inputStr) throws Exception {

		MessageDigest messageDigest = MessageDigest.getInstance("SHA-1");
		messageDigest.reset();
		messageDigest.update(inputStr.getBytes("UTF-8"));
		byte[] byteArray = messageDigest.digest();

		StringBuilder md5StrBuff = new StringBuilder();

		for (int i = 0; i < byteArray.length; i++) {
			if (Integer.toHexString(0xFF & byteArray[i]).length() == 1)
				md5StrBuff.append("0").append(String.format("%02X", byteArray[i]));
			else
				md5StrBuff.append(String.format("%02X", byteArray[i]));
		}

		return md5StrBuff.toString();
	}
	
	/**
	 * SHA验签
	 * @param data
	 * @param signature
	 * @return
	 * @throws Exception
	 */
	public static boolean verifySignature(String data, String signature) throws Exception {
		return signature.equals(getSHA1Code(data));
	}
}

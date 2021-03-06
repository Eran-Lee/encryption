package cn.eran.encryption;

import java.io.UnsupportedEncodingException;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.HashMap;

import cn.eran.encryption.util.AESUtil;
import cn.eran.encryption.util.DESUtil;
import cn.eran.encryption.util.MD5Util;
import cn.eran.encryption.util.RSAUtil;
import cn.eran.encryption.util.SHA1Util;

public class TestEncryption {
    private static final String KEY = "123456abc";  

	public static void main(String[] args) {
		System.out.println("----------------------------------DES--------------------------------");
		//待加密内容
		String str = "132321";
		//密码，长度要是8的倍数
		String password = "9588028820109132570743325311898426347857298773549468758875018579537757772163084478873699447306034466200616411960574122434059469100235892702736860872901247123456";

		byte[] result = DESUtil.encrypt(str.getBytes(), password);
		try {
			System.out.println("DES加密后内容：" + new String(result, "utf-8"));
		} catch (UnsupportedEncodingException e1) {
			e1.printStackTrace();
		}
		
		try {
			byte[] decryptRes = DESUtil.decrypt(result, password);
			System.out.println("DES解密后内容：" + new String(decryptRes));
		} catch (Exception e) {
			e.printStackTrace();
		}
		
		System.out.println("----------------------------------AES1--------------------------------");
		 	String content = "{'repairPhone':'18547854787','customPhone':'12365478965','captchav':'58m7'}";    
	        System.out.println("加密前：" + content);    
	        System.out.println("加密密钥和解密密钥：" + KEY);    
	        String encrypt = AESUtil.encrypt(content, KEY);    
	        System.out.println("加密后：" + encrypt);    
	        String decrypt = AESUtil.decrypt(encrypt, KEY);    
	        System.out.println("解密后：" + decrypt);  
	        
	    System.out.println("----------------------------------RSA--------------------------------");
        
	    HashMap<String, Object> map = null;
		try {
			map = RSAUtil.getKeys();
		} catch (NoSuchAlgorithmException e1) {
			e1.printStackTrace();
		}  
        //生成公钥和私钥  
        RSAPublicKey publicKey = (RSAPublicKey) map.get("public");  
        RSAPrivateKey privateKey = (RSAPrivateKey) map.get("private");  
          
        //模  
        String modulus = publicKey.getModulus().toString();  
        //公钥指数  
        String public_exponent = publicKey.getPublicExponent().toString();  
        //私钥指数  
        String private_exponent = privateKey.getPrivateExponent().toString();  
        //明文  
        String ming = "123456789";  
        //使用模和指数生成公钥和私钥  
        RSAPublicKey pubKey = RSAUtil.getPublicKey(modulus, public_exponent);  
        RSAPrivateKey priKey = RSAUtil.getPrivateKey(modulus, private_exponent);  
        //加密后的密文  
        String mi = null;
		try {
			mi = RSAUtil.encryptByPublicKey(ming, pubKey);
			ming = RSAUtil.decryptByPrivateKey(mi, priKey);  
		} catch (Exception e) {
		}  
        System.out.println("加密后：" + mi);  
        //解密后的明文  
        
        System.out.println("解密后：" + ming);  
	    
	    System.out.println("----------------------------------MD5签名--------------------------------");
	    System.out.println(MD5Util.MD5("123"));
	    System.out.println(MD5Util.md5Password("123")); //在线md5解析无法还原
	    boolean verify = MD5Util.verify("123", "77cd8fe8ee7cd43696d6a00219274026792122095a376875");
	    System.out.println(verify);
	    
	    System.out.println("----------------------------------SHA1签名--------------------------------");
	    System.out.println(SHA1Util.encode("123"));
	}

}

package cn.eran.encryption;

import java.io.UnsupportedEncodingException;

import cn.eran.encryption.util.AESUtil;
import cn.eran.encryption.util.DESUtil;

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
	        
	}

}

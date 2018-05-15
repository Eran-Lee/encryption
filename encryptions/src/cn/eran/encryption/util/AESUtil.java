package cn.eran.encryption.util;

import java.security.SecureRandom;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class AESUtil {
	
    private static final String defaultCharset = "UTF-8";  
    private static final String KEY_AES = "AES";  

  /** 
   * 加密 
   * 
   * @param data 需要加密的内容 
   * @param key 加密密码 
   * @return 
   */  
  public static String encrypt(String data, String key) {  
      return doAES(data, key, Cipher.ENCRYPT_MODE);  
  }  

  /** 
   * 解密 
   * 
   * @param data 待解密内容 
   * @param key 解密密钥 
   * @return 
   */  
  public static String decrypt(String data, String key) {  
      return doAES(data, key, Cipher.DECRYPT_MODE);  
  }  

  /** 
   * 加解密 
   * 
   * @param data 待处理数据 
   * @param password  密钥 
   * @param mode 加解密mode 
   * @return 
   */  
  private static String doAES(String data, String key, int mode) {  
      try {  
          //判断是加密还是解密  
          boolean encrypt = mode == Cipher.ENCRYPT_MODE;  
          byte[] content;  
          //true 加密内容 false 解密内容  
          if (encrypt) {  
              content = data.getBytes(defaultCharset);  
          } else {  
              content = parseHexStr2Byte(data);  
          }  
          //1.构造密钥生成器，指定为AES算法,不区分大小写  
          KeyGenerator kgen = KeyGenerator.getInstance(KEY_AES);  
          //2.根据ecnodeRules规则初始化密钥生成器  
          //生成一个128位的随机源,根据传入的字节数组  
          SecureRandom random = SecureRandom.getInstance("SHA1PRNG");
          random.setSeed(key.getBytes());
          kgen.init(128, random);  
//          kgen.init(128, new SecureRandom(key.getBytes()));  
          //3.产生原始对称密钥  
          SecretKey secretKey = kgen.generateKey();  
          //4.获得原始对称密钥的字节数组  
          byte[] enCodeFormat = secretKey.getEncoded();  
          //5.根据字节数组生成AES密钥  
          SecretKeySpec keySpec = new SecretKeySpec(enCodeFormat, KEY_AES);  
          //6.根据指定算法AES自成密码器  
          Cipher cipher = Cipher.getInstance(KEY_AES);// 创建密码器  
          //7.初始化密码器，第一个参数为加密(Encrypt_mode)或者解密解密(Decrypt_mode)操作，第二个参数为使用的KEY  
          cipher.init(mode, keySpec);// 初始化  
          byte[] result = cipher.doFinal(content);  
          if (encrypt) {
              //将二进制转换成16进制  
              return parseByte2HexStr(result);  
          } else {  
              return new String(result, defaultCharset);  
          }  
      } catch (Exception e) {  
    	  System.out.println("异常了");
      }  
      return null;  
  }  
  /** 
   * 将二进制转换成16进制 
   * 
   * @param buf 
   * @return 
   */  
  public static String parseByte2HexStr(byte buf[]) {  
      StringBuilder sb = new StringBuilder();  
      for (int i = 0; i < buf.length; i++) {  
          String hex = Integer.toHexString(buf[i] & 0xFF);  
          if (hex.length() == 1) {  
              hex = '0' + hex;  
          }  
          sb.append(hex.toUpperCase());  
      }  
      return sb.toString();  
  }  
  /** 
   * 将16进制转换为二进制 
   * 
   * @param hexStr 
   * @return 
   */  
  public static byte[] parseHexStr2Byte(String hexStr) {  
      if (hexStr.length() < 1) {  
          return null;  
      }  
      byte[] result = new byte[hexStr.length() / 2];  
      for (int i = 0; i < hexStr.length() / 2; i++) {  
          int high = Integer.parseInt(hexStr.substring(i * 2, i * 2 + 1), 16);  
          int low = Integer.parseInt(hexStr.substring(i * 2 + 1, i * 2 + 2), 16);  
          result[i] = (byte) (high * 16 + low);  
      }  
      return result;  
  } 
  
  //在使用过程中出现：javax.crypto.BadPaddingException: Given final block not properly padded
  //1. kgen.init(128, new SecureRandom(key.getBytes()));	------>>改为如下
  //    SecureRandom random = SecureRandom.getInstance("SHA1PRNG");
  //	random.setSeed(key.getBytes());
  
  /*2.在做加密解密过程中，报错了： javax.crypto.BadPaddingException: Given final block not properly padded 
  怎么回事，都是按照你的写的，怎么会不对呢？仔细分析一下，不难发现，该异常是在解密的时候抛出的，加密的方法没有问题。 

  但是两个方法的唯一差别是Cipher对象的模式不一样，这就排除了程序写错的可能性。再看一下异常的揭示信息，
  大概的意思是：提供的字块不符合填补的。什么意思？？？原来在用DES加密的时候，最后一位长度不足64的，
  它会自动填补到64，那么在我们进行字节数组到字串的转化过程中，可以把它填补的不可见字符改变了，
  所以引发系统抛出异常。问题找到，怎么解决呢？大家还记得邮件传输通常会把一些信息编码保存，
  对了，就是Base64，那样保证了信息的完整性，所以我们就是利用一下下了。为了方便使用，
  我们再写一个新的方法封装一下原来的方法： 

  public static String DataEncrypt(String str,byte[] key){ 
     String encrypt = null; 
     try{ 
     byte[] ret = encode(str.getBytes("UTF-8"),key); 
     encrypt = new String(Base64.encode(ret)); 
     }catch(Exception e){ 
     System.out.print(e); 
     encrypt = str; 
     } 
     return encrypt; 
     } 
    public static String DataDecrypt(String str,byte[] key){ 
     String decrypt = null; 
     try{ 
     byte[] ret =  decode(Base64.decode(str),key); 
     decrypt =  new String(ret,"UTF-8"); 
     }catch(Exception e){ 
     System.out.print(e); 
     decrypt = str; 
     } 
     return decrypt; 
     } 

  我们把方法的参数改成了字串，但是为什么要用UTF-8呢？不指定它的字节格式不行吗？大家知道，UTF-8是国际通用的字符编码，用它传输任何字串都不会有问题，通过它也可以很完美的解决J2EE的中文问题！所以我们最好用UTF-8编码，以减少不必要的麻烦。 

  注意，上面方法中当加密或者解密过程中，程序抛出异常，将返回原值，使得在调用方法失败时更方便的找出错误。 

  大家也可以利用其它的密钥，进行不同地方的加密解密 */


}

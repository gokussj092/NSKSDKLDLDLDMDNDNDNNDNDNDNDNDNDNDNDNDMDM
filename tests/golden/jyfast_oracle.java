// Independent normalization of JyFast APK 9 Rt.a/Rt.b, JCA instead of Android.
// No vendor payloads or binary code are included. Stdin: enc/dec, b64(key), b64(text).
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

class JyfastOracle {
 static final String SYMBOLS="!?-=∆×÷ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
 static final String STANDARD="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";
 static byte[] b64(String value){return Base64.getDecoder().decode(value);}
 static String text(byte[] value){return new String(value,StandardCharsets.UTF_8);}
 static String convert(String input,String from,String to){
  StringBuilder out=new StringBuilder();
  for(char c:input.toCharArray()){
   int n=from.indexOf(c);
   if(n<0 || n>=to.length())throw new IllegalArgumentException("symbol");
   out.append(to.charAt(n));
  }
  return out.toString();
 }
 static String run(String mode,String password,String value)throws Exception{
  Cipher cipher=Cipher.getInstance("AES/CBC/PKCS5Padding");
  byte[] key=MessageDigest.getInstance("SHA-256").digest(password.getBytes(StandardCharsets.UTF_8));
  cipher.init(mode.equals("enc")?Cipher.ENCRYPT_MODE:Cipher.DECRYPT_MODE,
   new SecretKeySpec(key,"AES"),new IvParameterSpec(new byte[16]));
  if(mode.equals("enc"))return convert(Base64.getEncoder().encodeToString(cipher.doFinal(value.getBytes(StandardCharsets.UTF_8))),STANDARD,SYMBOLS);
  if(!mode.equals("dec"))throw new IllegalArgumentException("mode");
  return text(cipher.doFinal(b64(convert(value,SYMBOLS,STANDARD))));
 }
 public static void main(String[] args)throws Exception{
  BufferedReader reader=new BufferedReader(new InputStreamReader(System.in,StandardCharsets.UTF_8));
  for(String line;(line=reader.readLine())!=null;){
   String[] parts=line.split("\t",-1);
   String result=run(parts[0],text(b64(parts[1])),text(b64(parts[2])));
   System.out.println(Base64.getEncoder().encodeToString(result.getBytes(StandardCharsets.UTF_8)));
  }
 }
}

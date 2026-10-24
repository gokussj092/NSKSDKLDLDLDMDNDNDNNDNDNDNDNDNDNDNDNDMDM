// Independent normalized ProNeet 27.11 AESCrypt: custom alphabet and JCA CBC.
// Synthetic vectors only. Real catalog data is never stored in this source.
import java.io.*;import java.nio.charset.*;import java.security.*;import java.util.*;
import javax.crypto.*;import javax.crypto.spec.*;
class ProNeetOracle {
 static final String SYMBOLS="!?-=∆×÷ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
 static final String STANDARD="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";
 static byte[] bytes(String s){return s.getBytes(StandardCharsets.UTF_8);}
 static String translate(String text,boolean decode){
  String from=decode?SYMBOLS:STANDARD,to=decode?STANDARD:SYMBOLS;StringBuilder out=new StringBuilder();
  for(char c:text.toCharArray()){int i=from.indexOf(c);if(i<0||i>64)throw new IllegalArgumentException("alphabet");out.append(to.charAt(i));}return out.toString();
 }
 static String crypt(String text,String password,boolean decode)throws Exception{
  byte[] key=MessageDigest.getInstance("SHA-256").digest(bytes(password));
  Cipher c=Cipher.getInstance("AES/CBC/PKCS5Padding");c.init(decode?2:1,new SecretKeySpec(key,"AES"),new IvParameterSpec(new byte[16]));
  return decode?new String(c.doFinal(Base64.getDecoder().decode(translate(text.trim(),true))),StandardCharsets.UTF_8):
    translate(Base64.getEncoder().encodeToString(c.doFinal(bytes(text))),false);
 }
 public static void main(String[]args)throws Exception{
  BufferedReader reader=new BufferedReader(new InputStreamReader(System.in,StandardCharsets.UTF_8));String line;
  while((line=reader.readLine())!=null){String[] p=line.split("\t",-1);String text=new String(Base64.getDecoder().decode(p[1]),StandardCharsets.UTF_8);
   boolean field=p[0].startsWith("field"),decode=!p[0].endsWith("-encrypt");
   if(!Set.of("field","field-encrypt","outer","outer-encrypt").contains(p[0]))throw new IllegalArgumentException("command");
   String value=field&&text.isEmpty()?text:crypt(text,field?"Key: =Kenova_code":"Proneet",decode);
   System.out.println(Base64.getEncoder().encodeToString(bytes(value)));
  }
 }
}

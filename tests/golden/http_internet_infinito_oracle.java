// Independent JDK transcription of APK p083u2.c/d and g's UTF-16 rotation.
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.*;
import javax.crypto.Cipher;
import javax.crypto.spec.*;
class http_internet_infinito_oracle {
 static byte[] utf(String s){return s.getBytes(StandardCharsets.UTF_8);}
 static String rotate(String s,int step){
  StringBuilder out=new StringBuilder();for(int i=0;i<s.length();i++){
   char c=s.charAt(i);if(Character.isLetter(c)){int base=Character.isUpperCase(c)?65:97;c=(char)((c+step-base)%26+base);}out.append(c);
  }return out.toString();
 }
 static byte[] material(byte[] salt)throws Exception{
  ByteArrayOutputStream out=new ByteArrayOutputStream();byte[] prev=new byte[0];
  while(out.size()<48){MessageDigest m=MessageDigest.getInstance("MD5");m.update(prev);m.update(utf("eDios12@gokum"));m.update(salt);prev=m.digest();out.write(prev);}return out.toByteArray();
 }
 static String apply(String op,String text)throws Exception{
  boolean seal=op.startsWith("seal-");boolean field=op.endsWith("field");
  byte[] salt=utf("test1234"),iv,key,input;
  if(field){key=Arrays.copyOf(utf("SonGok@$!sN@gD4l"),32);iv=new byte[16];}
  else{if(!seal){byte[] raw=Base64.getDecoder().decode(text.strip());if(!new String(raw,0,8,StandardCharsets.US_ASCII).equals("WakkoDev"))throw new IllegalArgumentException();salt=Arrays.copyOfRange(raw,8,16);}byte[] m=material(salt);key=Arrays.copyOf(m,32);iv=Arrays.copyOfRange(m,32,48);}
  if(seal)input=utf(field?rotate(text,4):text);
  else if(field){byte[] raw=Base64.getUrlDecoder().decode(text.replaceAll("\\s", ""));iv=Arrays.copyOf(raw,16);input=Arrays.copyOfRange(raw,16,raw.length);}
  else{byte[] raw=Base64.getDecoder().decode(text.strip());input=Arrays.copyOfRange(raw,16,raw.length);}
  Cipher c=Cipher.getInstance("AES/CBC/PKCS5Padding");c.init(seal?1:2,new SecretKeySpec(key,"AES"),new IvParameterSpec(iv));byte[] raw=c.doFinal(input);
  if(!seal){String s=new String(raw,StandardCharsets.UTF_8);return field?rotate(s,22):s;}
  ByteArrayOutputStream out=new ByteArrayOutputStream();if(field)out.write(iv);else{out.write(utf("WakkoDev"));out.write(salt);}out.write(raw);
  return field?Base64.getUrlEncoder().withoutPadding().encodeToString(out.toByteArray()):Base64.getEncoder().encodeToString(out.toByteArray());
 }
 public static void main(String[]args)throws Exception{
  BufferedReader r=new BufferedReader(new InputStreamReader(System.in,StandardCharsets.UTF_8));String line;
  while((line=r.readLine())!=null){String[]p=line.split("\t",2);String s=new String(Base64.getDecoder().decode(p[1]),StandardCharsets.UTF_8);System.out.println(Base64.getEncoder().encodeToString(utf(apply(p[0],s))));}
 }
}

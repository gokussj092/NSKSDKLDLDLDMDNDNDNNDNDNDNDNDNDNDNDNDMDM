import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.*;
import javax.crypto.*;
import javax.crypto.spec.*;
/** Independent JCA transcript of gb.a, gb.m$a and g3.r; synthetic secrets only. */
class alfaisal_oracle {
 static byte[] key;
 static {try{key=MessageDigest.getInstance("SHA-256").digest("#ALFAISAL VPN (FREE) 2020#".getBytes(StandardCharsets.UTF_8));}catch(Exception e){throw new RuntimeException(e);}}
 static byte[] cbc(byte[] raw,boolean seal)throws Exception{
  Cipher c=Cipher.getInstance("AES/CBC/PKCS5Padding");
  c.init(seal?Cipher.ENCRYPT_MODE:Cipher.DECRYPT_MODE,new SecretKeySpec(key,"AES"),new IvParameterSpec(new byte[16]));return c.doFinal(raw);
 }
 static byte[] mode(int m,byte[] raw)throws Exception{
  if(m==0)return cbc(Base64.getMimeDecoder().decode(raw),false);
  if(m==1)return Base64.getEncoder().encode(cbc(raw,true));
  if(m==2){
   // APK gb.m$a.b returns its input for CBC GeneralSecurityException.
   byte[] ct=Base64.getMimeDecoder().decode(raw);
   try{return cbc(ct,false);}catch(GeneralSecurityException e){return raw;}
  }
  if(m==3){
   String[] p=new String(raw,StandardCharsets.UTF_8).split("\\t",4);
   Mac mac=Mac.getInstance("HmacSHA256");mac.init(new SecretKeySpec(p[0].getBytes(StandardCharsets.UTF_8),"HmacSHA256"));
   return HexFormat.of().formatHex(mac.doFinal((p[1]+"."+p[2]+"."+p[3]).getBytes(StandardCharsets.UTF_8))).getBytes(StandardCharsets.US_ASCII);
  }
  throw new IllegalArgumentException("mode");
 }
 public static void main(String[]a)throws Exception{
  var r=new BufferedReader(new InputStreamReader(System.in,StandardCharsets.UTF_8));String line;
  while((line=r.readLine())!=null){String[] p=line.split("\\t",2);System.out.println(Base64.getEncoder().encodeToString(mode(Integer.parseInt(p[0]),Base64.getDecoder().decode(p[1]))));}
 }
}

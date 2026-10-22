// Independent JDK implementation of build-59 AESCrypt and first SSLdirecto key.
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.*;
import javax.crypto.Cipher;
import javax.crypto.spec.*;
class focus_vpn_cloud_oracle {
 static final String ALPHABET="▙▚▛▜▝▞▟▃▄▅▆▇█▉▊▐";
 static byte[] key()throws Exception{
  StringBuilder h=new StringBuilder();for(byte b:"@StrintApp1".getBytes(StandardCharsets.UTF_8))h.append(String.format("%02X",b&255));
  return MessageDigest.getInstance("SHA-256").digest(h.toString().getBytes(StandardCharsets.UTF_8));
 }
 static String apply(String op,String text)throws Exception{
  boolean seal=op.startsWith("seal-");boolean field=op.endsWith("field");
  Cipher c=Cipher.getInstance(field?"RC4":"AES/CBC/PKCS5Padding");
  if(field)c.init(seal?1:2,new SecretKeySpec(Arrays.copyOf("null".getBytes(StandardCharsets.UTF_8),16),"RC4"));
  else c.init(seal?1:2,new SecretKeySpec(key(),"AES"),new IvParameterSpec(new byte[16]));
  byte[] input;
  if(seal)input=text.getBytes(StandardCharsets.UTF_8);
  else if(field)input=Base64.getDecoder().decode(text.replaceAll("\\s", ""));
  else{
   String t=text.replaceAll("\\s","");byte[] raw=new byte[t.length()/2];
   for(int i=0;i<raw.length;i++)raw[i]=(byte)(ALPHABET.indexOf(t.charAt(2*i))*16+ALPHABET.indexOf(t.charAt(2*i+1)));
   input=Base64.getDecoder().decode(raw);
  }
  byte[] out=c.doFinal(input);if(!seal)return new String(out,StandardCharsets.UTF_8);
  String b64=Base64.getEncoder().encodeToString(out);if(field)return b64;
  StringBuilder encoded=new StringBuilder();for(byte b:b64.getBytes(StandardCharsets.US_ASCII))encoded.append(ALPHABET.charAt((b&255)>>>4)).append(ALPHABET.charAt(b&15));return encoded.toString();
 }
 public static void main(String[]args)throws Exception{
  BufferedReader r=new BufferedReader(new InputStreamReader(System.in,StandardCharsets.UTF_8));String line;
  while((line=r.readLine())!=null){String[]p=line.split("\t",2);String text=new String(Base64.getDecoder().decode(p[1]),StandardCharsets.UTF_8);System.out.println(Base64.getEncoder().encodeToString(apply(p[0],text).getBytes(StandardCharsets.UTF_8)));}
 }
}

// Normalized Java oracle from OnSpace VPN 4.2 APK call paths; synthetic data only.
// Android Base64 -> JDK Base64; AES PKCS7 -> JDK PKCS5 (same AES padding).
import java.nio.charset.*;import java.security.*;import java.util.*;import java.io.*;import javax.crypto.*;import javax.crypto.spec.*;
class OnSpaceOracle {
 static final String ALPHABET="@#$_&-+()/*\"!:;?";
 static byte[] b64(String s){return Base64.getDecoder().decode(s);}
 static String enc(byte[] b){return Base64.getEncoder().encodeToString(b);}
 static byte[] ascii(String s){return s.getBytes(StandardCharsets.UTF_8);}
 static byte[] outerKey() throws Exception {
  StringBuilder hex=new StringBuilder();for(byte b:ascii("netconexionestunnel"))hex.append(String.format("%02X",b&255));
  return MessageDigest.getInstance("SHA-256").digest(ascii(hex.toString()));
 }
 static String outer(String text) throws Exception {
  text=text.trim();byte[] raw=new byte[text.length()/2];
  for(int i=0;i<raw.length;i++)raw[i]=(byte)((ALPHABET.indexOf(text.charAt(i*2))<<4)+ALPHABET.indexOf(text.charAt(i*2+1)));
  Cipher c=Cipher.getInstance("AES/CBC/PKCS5Padding");c.init(2,new SecretKeySpec(outerKey(),"AES"),new IvParameterSpec(new byte[16]));
  return new String(c.doFinal(b64(new String(raw,StandardCharsets.US_ASCII))),StandardCharsets.UTF_8);
 }
 static String outerEncrypt(String text) throws Exception {
  Cipher c=Cipher.getInstance("AES/CBC/PKCS5Padding");c.init(1,new SecretKeySpec(outerKey(),"AES"),new IvParameterSpec(new byte[16]));
  StringBuilder s=new StringBuilder();for(byte b:ascii(enc(c.doFinal(ascii(text))))){s.append(ALPHABET.charAt((b&255)>>>4));s.append(ALPHABET.charAt(b&15));}return s.toString();
 }
 static String field(String s) throws Exception {
  Cipher c=Cipher.getInstance("AES/CBC/PKCS5Padding");c.init(2,new SecretKeySpec(ascii("speedtunnel@2406"),"AES"),new IvParameterSpec(new byte[16]));
  return rotate(new String(c.doFinal(b64(s)),StandardCharsets.UTF_8),24);
 }
 static String fieldEncrypt(String s) throws Exception {
  Cipher c=Cipher.getInstance("AES/CBC/PKCS5Padding");c.init(1,new SecretKeySpec(ascii("speedtunnel@2406"),"AES"),new IvParameterSpec(new byte[16]));
  return enc(c.doFinal(ascii(rotate(s,2))));
 }
    public static String rotate(String str, int i) {
        StringBuilder sb = new StringBuilder();
        for (int i2 = 0; i2 < str.length(); i2++) {
            char cCharAt = str.charAt(i2);
            if (!Character.isLetter(cCharAt)) {
                sb.append(cCharAt);
            } else if (Character.isUpperCase(cCharAt)) {
                sb.append((char) ((((cCharAt + i) - 65) % 26) + 65));
            } else {
                sb.append((char) ((((cCharAt + i) - 97) % 26) + 97));
            }
        }
        return sb.toString();
    }


 public static void main(String[] args) throws Exception {
  BufferedReader r=new BufferedReader(new InputStreamReader(System.in,StandardCharsets.UTF_8));String line;
  while((line=r.readLine())!=null){String[] p=line.split("\t",-1);String s=new String(b64(p[1]),StandardCharsets.UTF_8);String v;
   switch(p[0]) {
    case "outer":v=outer(s);break;
    case "outer-encrypt":v=outerEncrypt(s);break;
    case "field":v=s.isEmpty()?s:field(s);break;
    case "field-encrypt":v=s.isEmpty()?s:fieldEncrypt(s);break;
    case "rotate":v=rotate(s,24);break;
    case "field-seal":
     Cipher c=Cipher.getInstance("AES/CBC/PKCS5Padding");c.init(1,new SecretKeySpec(ascii("speedtunnel@2406"),"AES"),new IvParameterSpec(new byte[16]));v=enc(c.doFinal(ascii(s)));break;
    default:throw new IllegalArgumentException("command");
   }
   System.out.println(enc(ascii(v)));
  }
 }
}

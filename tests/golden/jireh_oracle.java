// Normalized Java oracle from HTTP Jireh 2.0 APK call paths; synthetic data only.
// Android Base64 -> JDK Base64; AES PKCS7 -> JDK PKCS5 (same AES padding).
import java.nio.charset.*;import java.security.*;import java.util.*;import java.io.*;import javax.crypto.*;import javax.crypto.spec.*;
class JirehOracle {
 static final String ALPHABET="@#$_&-+()/*\"!:;?";
 static byte[] b64(String s){return Base64.getDecoder().decode(s);}
 static String enc(byte[] b){return Base64.getEncoder().encodeToString(b);}
 static byte[] ascii(String s){return s.getBytes(StandardCharsets.UTF_8);}
 static byte[] outerKey() throws Exception {
  StringBuilder hex=new StringBuilder();for(byte b:ascii("Conexcol@45208!"))hex.append(String.format("%02X",b&255));
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
  Cipher c=Cipher.getInstance("AES/CBC/PKCS5Padding");c.init(2,new SecretKeySpec(ascii("conexcolvpn@2308"),"AES"),new IvParameterSpec(new byte[16]));
  return rotate(new String(c.doFinal(b64(s)),StandardCharsets.UTF_8),22);
 }
 static String fieldEncrypt(String s) throws Exception {
  Cipher c=Cipher.getInstance("AES/CBC/PKCS5Padding");c.init(1,new SecretKeySpec(ascii("conexcolvpn@2308"),"AES"),new IvParameterSpec(new byte[16]));
  return enc(c.doFinal(ascii(rotate(s,4))));
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


 static byte[] profileKey(byte[] salt) throws Exception {return SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256").generateSecret(new PBEKeySpec("fubvx788b46v".toCharArray(),salt,1000,128)).getEncoded();}
 static String profileEncrypt(String xml) throws Exception {
  byte[] salt=new byte[32],nonce=new byte[12];for(int i=0;i<32;i++)salt[i]=(byte)(i+1);for(int i=0;i<12;i++)nonce[i]=(byte)(i+97);
  Cipher c=Cipher.getInstance("AES/GCM/NoPadding");c.init(1,new SecretKeySpec(profileKey(salt),"AES"),new GCMParameterSpec(128,nonce));
  return enc(salt)+"."+enc(nonce)+"."+enc(c.doFinal(ascii(xml)));
 }
 static String profileDecrypt(String text) throws Exception {
  String[] p=text.split("\\.");Cipher c=Cipher.getInstance("AES/GCM/NoPadding");c.init(2,new SecretKeySpec(profileKey(b64(p[0])),"AES"),new GCMParameterSpec(128,b64(p[1])));return new String(c.doFinal(b64(p[2])),StandardCharsets.UTF_8);
 }
 static byte[] des(byte[] b,int mode) throws Exception {Cipher c=Cipher.getInstance("DES/ECB/PKCS5Padding");c.init(mode,new SecretKeySpec(ascii("cinbdf66"),"DES"));return c.doFinal(b);}
 public static void main(String[] a) throws Exception {
  BufferedReader r=new BufferedReader(new InputStreamReader(System.in,StandardCharsets.UTF_8));String line;
  while((line=r.readLine())!=null){String[] p=line.split("\t",-1);String s=new String(b64(p[1]),StandardCharsets.UTF_8);String v;
   switch(p[0]) {
    case "outer":v=outer(s);break;
    case "outer-encrypt":v=outerEncrypt(s);break;
    case "field":v=field(s);break;
    case "field-encrypt":v=fieldEncrypt(s);break;
    case "rotate":v=rotate(s,22);break;
    case "profile-encrypt":v=profileEncrypt(s);break;
    case "profile-decrypt":v=profileDecrypt(s);break;
    case "des-encrypt":v=enc(des(ascii(s),1));break;
    case "des-decrypt":v=new String(des(b64(s),2),StandardCharsets.UTF_8);break;
    default:throw new IllegalArgumentException("command");
   }
   System.out.println(enc(ascii(v)));
  }
 }
}

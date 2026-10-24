// Independent JDK implementation normalized from HTTP Wakko 4.9 Java/ARM64 paths.
// Synthetic vectors only. No APK, native library or downloaded user content needed.
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.*;
import javax.crypto.*;
import javax.crypto.spec.*;
class wakko_oracle {
  static final java.nio.charset.Charset UTF8 = StandardCharsets.UTF_8;
  static final String SECRET = "NJ22pX9mQaWK7Rt4Vz8HyLcDuK";
  static final String PASSWORD = "\u26a1\ud83d\udc95NAJU\u2764\ufe0f221223\ud83d\udc95\u26a1";
  static final byte[] CHACHA = HexFormat.of().parseHex("93275eb144c8196aef027d35a9581cd46fb7218a3ec59014da734be20f619d28");
  static byte[] b64(String s) { return Base64.getDecoder().decode(s); }
  static byte[] ub64(String s) { return Base64.getUrlDecoder().decode(s); }
  static String uenc(byte[] b) { return Base64.getUrlEncoder().withoutPadding().encodeToString(b); }
  static byte[] seq(int count, int start) { byte[] b=new byte[count];for(int i=0;i<count;i++)b[i]=(byte)(start+i);return b; }
  static byte[] cat(byte[] a,byte[] b) { byte[] out=Arrays.copyOf(a,a.length+b.length);System.arraycopy(b,0,out,a.length,b.length);return out; }
  static byte[] key(String version)throws Exception {
    byte[] hash=MessageDigest.getInstance("SHA-256").digest((SECRET+version).getBytes(UTF8));
    String alphabet="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";StringBuilder s=new StringBuilder();
    for(int i=0;i<16;i++)s.append(alphabet.charAt((hash[i]&255)%62));return Arrays.copyOf(s.toString().getBytes(UTF8),32);
  }
  static byte[] aes(boolean enc,byte[] key,byte[] iv,byte[] data)throws Exception {
    Cipher c=Cipher.getInstance("AES/CBC/PKCS5Padding");c.init(enc?Cipher.ENCRYPT_MODE:Cipher.DECRYPT_MODE,new SecretKeySpec(key,"AES"),new IvParameterSpec(iv));return c.doFinal(data);
  }
  static byte[] chacha(boolean enc,byte[] data)throws Exception {
    byte[] nonce=enc?seq(12,33):Arrays.copyOf(data,12);
    Cipher c=Cipher.getInstance("ChaCha20-Poly1305");c.init(enc?Cipher.ENCRYPT_MODE:Cipher.DECRYPT_MODE,new SecretKeySpec(CHACHA,"ChaCha20"),new IvParameterSpec(nonce));
    byte[] out=c.doFinal(enc?data:Arrays.copyOfRange(data,12,data.length));return enc?cat(nonce,out):out;
  }
  static String rotate(String text,int shift) {
    StringBuilder s=new StringBuilder();for(int i=0;i<text.length();i++) {
      char c=text.charAt(i);if(Character.isLetter(c)) { int start=Character.isUpperCase(c)?65:97;c=(char)((c+shift-start)%26+start); }s.append(c);
    }return s.toString();
  }
  static String encryptField(String v,String text,boolean wrap)throws Exception {
    byte[] iv=seq(16,11);String inner=uenc(cat(iv,aes(true,key(v),iv,rotate(text,7).getBytes(UTF8))));
    return wrap?uenc(chacha(true,inner.getBytes(UTF8))):inner;
  }
  static String field(String v,String text)throws Exception {
    if(text.isEmpty())return text;
    byte[] raw=ub64(text);if(raw.length%16!=0)raw=ub64(new String(chacha(false,raw),UTF8).trim());
    return rotate(new String(aes(false,key(v),Arrays.copyOf(raw,16),Arrays.copyOfRange(raw,16,raw.length)),UTF8),19);
  }
  static byte[] outer(boolean enc,byte[] data)throws Exception {
    byte[] raw=enc?data:b64(new String(data,UTF8).trim());byte[] salt=enc?seq(8,71):Arrays.copyOfRange(raw,8,16);
    byte[] material=new byte[0],last=new byte[0];MessageDigest md=MessageDigest.getInstance("MD5");
    while(material.length<48) {last=md.digest(cat(cat(last,PASSWORD.getBytes(UTF8)),salt));material=cat(material,last);}
    byte[] out=aes(enc,Arrays.copyOf(material,32),Arrays.copyOfRange(material,32,48),enc?raw:Arrays.copyOfRange(raw,16,raw.length));
    return enc?Base64.getEncoder().encode(cat(cat("WakkoDev".getBytes(UTF8),salt),out)):out;
  }
  public static void main(String[] args)throws Exception {
    BufferedReader in=new BufferedReader(new InputStreamReader(System.in,UTF8));String line;
    while((line=in.readLine())!=null) {
      String[] p=line.split("\t",-1);String a=new String(b64(p[1]),UTF8);byte[] out;
      switch(p[0]) {
        case "key":out=key(a);break;
        case "outer":out=outer(false,b64(p[1]));break;
        case "outer-encrypt":out=outer(true,b64(p[1]));break;
        case "field":out=field(a,new String(b64(p[2]),UTF8)).getBytes(UTF8);break;
        case "field-encrypt":out=encryptField(a,new String(b64(p[2]),UTF8),true).getBytes(UTF8);break;
        case "field-direct":out=encryptField(a,new String(b64(p[2]),UTF8),false).getBytes(UTF8);break;
        case "rotate":out=rotate(a,19).getBytes(UTF8);break;
        default:throw new IllegalArgumentException("Unknown test operation");
      }
      System.out.println(Base64.getEncoder().encodeToString(out));
    }
  }
}

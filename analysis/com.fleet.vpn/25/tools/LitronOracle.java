/* Own independent JCA oracle for the public q.f format; never runs APK classes. */
import java.io.*;import java.nio.*;import java.nio.charset.*;import java.nio.file.*;import java.security.*;
import java.util.*;import javax.crypto.*;import javax.crypto.spec.*;
class LitronOracle {
 static final String SEED="godtech25";
 static String utf(byte[] b)throws Exception{return StandardCharsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT).onUnmappableCharacter(CodingErrorAction.REPORT).decode(ByteBuffer.wrap(b)).toString();}
 static byte[] key()throws Exception{return MessageDigest.getInstance("SHA-256").digest(HexFormat.of().withUpperCase().formatHex(SEED.getBytes(StandardCharsets.UTF_8)).getBytes(StandardCharsets.US_ASCII));}
 static byte[] crypt(byte[] b,int mode)throws Exception{Cipher c=Cipher.getInstance("AES/CBC/PKCS5Padding");c.init(mode,new SecretKeySpec(key(),"AES"),new IvParameterSpec(new byte[16]));return c.doFinal(b);}
 static byte[] unpack(String s){if(s.isEmpty()||s.length()%2!=0)throw new IllegalArgumentException("carrier");byte[] out=new byte[s.length()/2];for(int i=0;i<out.length;i++){int a=s.charAt(i*2)-0x2000,b=s.charAt(i*2+1)-0x2000;if(a<0||a>15||b<0||b>15)throw new IllegalArgumentException("alphabet");out[i]=(byte)(a*16+b);}return out;}
 static String pack(byte[] raw){StringBuilder s=new StringBuilder();for(byte b:raw){s.append((char)(0x2000+((b&255)>>>4)));s.append((char)(0x2000+(b&15)));}return s.toString();}
 static String hidden(String value)throws Exception{
  if(value.isEmpty()||!value.chars().allMatch(c->c>=0x2000&&c<=0x200f))return value;
  byte[] raw;try{raw=unpack(value);}catch(Exception e){return value;}
  List<byte[]> candidates=new ArrayList<>();try{candidates.add(Base64.getDecoder().decode(raw));}catch(Exception e){}
  candidates.add(raw);
  for(byte[] b:candidates){if(b.length==0||b.length%16!=0)continue;try{return utf(crypt(b,Cipher.DECRYPT_MODE));}catch(Exception e){}}
  try{return utf(raw);}catch(Exception e){return value;}
 }
 public static void main(String[]args)throws Exception{
  try(var lines=Files.lines(Path.of(args[0]),StandardCharsets.UTF_8)){
   for(String line:(Iterable<String>)lines::iterator){String[] p=line.split("\t",-1);String value=utf(Base64.getDecoder().decode(p[1]));String out;
    switch(p[0]){
     case "open":out=utf(crypt(Base64.getDecoder().decode(unpack(value)),Cipher.DECRYPT_MODE));break;
     case "hidden":out=hidden(value);break;
     case "seal":out=pack(Base64.getEncoder().encode(crypt(value.getBytes(StandardCharsets.UTF_8),Cipher.ENCRYPT_MODE)));break;
     case "seal-raw":out=pack(crypt(value.getBytes(StandardCharsets.UTF_8),Cipher.ENCRYPT_MODE));break;
     case "plain-hidden":out=pack(value.getBytes(StandardCharsets.UTF_8));break;
     default:throw new IllegalArgumentException("mode");
    }
    System.out.println(Base64.getEncoder().encodeToString(out.getBytes(StandardCharsets.UTF_8)));
   }
  }
 }
}

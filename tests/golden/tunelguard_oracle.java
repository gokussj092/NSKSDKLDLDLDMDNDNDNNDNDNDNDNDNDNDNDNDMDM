// Independent JCA oracle normalized from TunelGuard build 128 JNI and Java callers.
// Synthetic generation only; build constants do not come from downloaded accounts.
import java.io.*;
import java.util.*;
import java.nio.charset.StandardCharsets;
import javax.crypto.*;
import javax.crypto.spec.*;
class tunelguard_oracle {
 static final byte[] CK=HexFormat.of().parseHex("c09300e6f86c0e11c9bf709289481023d57655095bf2b7452204bb2e3d623ede"),FK=HexFormat.of().parseHex("5447565f555345525f43304e4631475f");
 static final java.nio.charset.Charset UTF8=StandardCharsets.UTF_8;
 static final byte[] PREFIX="STGCM2.TG.".getBytes(UTF8);
 static byte[] seq(int n){byte[] b=new byte[n];for(int i=0;i<n;i++)b[i]=(byte)(i+37);return b;}
 static String xor(String s){StringBuilder b=new StringBuilder();int[] m={30482,14551,22566,65535};for(int i=0;i<s.length();i++)b.append((char)(s.charAt(i)^m[i%4]));return b.toString();}
 static String ab64(String s){String b=Base64.getEncoder().encodeToString(s.getBytes(UTF8));StringBuilder out=new StringBuilder();for(int i=0;i<b.length();i+=76)out.append(b.substring(i,Math.min(i+76,b.length()))).append('\n');return out.toString();}
 static String double64(String s){return ab64(ab64(s));}
 static byte[] mutf(String s)throws Exception{ByteArrayOutputStream b=new ByteArrayOutputStream();new DataOutputStream(b).writeUTF(s);return Arrays.copyOfRange(b.toByteArray(),2,b.size());}
 static String unmutf(byte[] b)throws Exception{ByteArrayOutputStream o=new ByteArrayOutputStream();DataOutputStream d=new DataOutputStream(o);d.writeShort(b.length);d.write(b);return new DataInputStream(new ByteArrayInputStream(o.toByteArray())).readUTF();}
 static String catalog(String s,boolean enc)throws Exception{
  byte[] nonce=seq(12),body=s.getBytes(UTF8);if(!enc){String[] p=s.split("\\.");nonce=Base64.getUrlDecoder().decode(p[2]);body=Base64.getUrlDecoder().decode(p[3]);}
  Cipher c=Cipher.getInstance("AES/GCM/NoPadding");c.init(enc?1:2,new SecretKeySpec(CK,"AES"),new GCMParameterSpec(128,nonce));c.updateAAD(PREFIX);byte[] out=c.doFinal(body);
  return enc?"STGCM2.TG."+Base64.getUrlEncoder().withoutPadding().encodeToString(nonce)+"."+Base64.getUrlEncoder().withoutPadding().encodeToString(out):new String(out,UTF8);
 }
 static String file(String s,boolean enc)throws Exception{
  byte[] iv=seq(16),body=enc?mutf(s):Base64.getMimeDecoder().decode(s);if(!enc){iv=Arrays.copyOf(body,16);body=Arrays.copyOfRange(body,16,body.length);}
  Cipher c=Cipher.getInstance("AES/CBC/PKCS5Padding");c.init(enc?1:2,new SecretKeySpec(FK,"AES"),new IvParameterSpec(iv));byte[] out=c.doFinal(body);
  if(!enc)return unmutf(out);byte[] raw=Arrays.copyOf(iv,16+out.length);System.arraycopy(out,0,raw,16,out.length);return Base64.getEncoder().encodeToString(raw);
 }
 public static void main(String[] a)throws Exception{
  BufferedReader r=new BufferedReader(new InputStreamReader(System.in,UTF8));String l;while((l=r.readLine())!=null){String[] p=l.split("\t",-1);String s=new String(Base64.getDecoder().decode(p[1]),UTF8),out;
   switch(p[0]){case "catalog":out=catalog(s,false);break;case "catalog-encrypt":out=catalog(s,true);break;case "file":out=file(s,false);break;case "file-encrypt":out=file(s,true);break;case "xor":out=xor(s);break;case "double":out=double64(s);break;default:throw new IllegalArgumentException();}
   System.out.println(Base64.getEncoder().encodeToString(out.getBytes(UTF8)));
  }
 }
}

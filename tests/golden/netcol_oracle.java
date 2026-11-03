// Independent JCA normalization of Netcol build 142's catalog/field recipes.
// Stdin: enc/dec TAB catalog/field/user TAB Base64(UTF8 input).
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.*;
import javax.crypto.Cipher;
import javax.crypto.spec.*;
class NetcolOracle {
 static final String ABC="▙▚▛▜▝▞▟▃▄▅▆▇█▉▊▐";
 static byte[] bytes(String s){return s.getBytes(StandardCharsets.UTF_8);}
 static String text(byte[] b){return new String(b,StandardCharsets.UTF_8);}
 static String hex(byte[] b){StringBuilder s=new StringBuilder();for(byte x:b)s.append(String.format("%02X",x&255));return s.toString();}
 static String symbols(byte[] b){StringBuilder s=new StringBuilder();for(byte x:b){s.append(ABC.charAt((x&255)>>>4));s.append(ABC.charAt(x&15));}return s.toString();}
 static byte[] unpack(String s){
  if(s.length()%2!=0)throw new IllegalArgumentException();
  byte[] b=new byte[s.length()/2];
  for(int i=0;i<b.length;i++){int a=ABC.indexOf(s.charAt(2*i)),c=ABC.indexOf(s.charAt(2*i+1));if(a<0||c<0)throw new IllegalArgumentException();b[i]=(byte)(16*a+c);}return b;
 }
 static String run(String op,String mode,String input)throws Exception{
  boolean enc=op.equals("enc"),catalog=mode.equals("catalog");
  if(!enc&&!op.equals("dec"))throw new IllegalArgumentException();
  if(!catalog&&!mode.equals("user")&&!mode.equals("field"))throw new IllegalArgumentException();
  byte[] key=catalog?MessageDigest.getInstance("SHA-256").digest(bytes(hex(bytes("FamiliaGelves24")))):bytes(mode.equals("user")?"LiamSebas18":"UniversalPro24");
  Cipher c=Cipher.getInstance(catalog?"AES/CBC/PKCS5Padding":"Blowfish/CBC/PKCS5Padding");
  c.init(enc?Cipher.ENCRYPT_MODE:Cipher.DECRYPT_MODE,new SecretKeySpec(key,catalog?"AES":"Blowfish"),new IvParameterSpec(catalog?new byte[16]:bytes("abcdefgh")));
  if(enc){String b64=Base64.getEncoder().encodeToString(c.doFinal(bytes(input)));return catalog?symbols(bytes(b64)):b64;}
  return text(c.doFinal(Base64.getDecoder().decode(catalog?unpack(input):bytes(input))));
 }
 public static void main(String[]args)throws Exception{
  var r=new BufferedReader(new InputStreamReader(System.in,StandardCharsets.UTF_8));
  for(String line;(line=r.readLine())!=null;){String[] p=line.split("\t",-1);System.out.println(Base64.getEncoder().encodeToString(bytes(run(p[0],p[1],text(Base64.getDecoder().decode(p[2]))))));}
 }
}

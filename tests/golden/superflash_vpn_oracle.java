// AESED and Servers.encoder normalized from SuperFlash VPN 184.0.1.
// Tab-separated commands/Base64 input; output is Base64. No Android execution.
import java.nio.charset.*;import java.util.*;import java.io.*;import javax.crypto.*;import javax.crypto.spec.*;
class SuperFlashOracle {
 static byte[] utf(String s){return s.getBytes(StandardCharsets.UTF_8);}
 static String rotate(String s,int shift){
  StringBuilder out=new StringBuilder();
  for(int i=0;i<s.length();i++){
   char c=s.charAt(i);int base=Character.isUpperCase(c)?65:97;
   out.append(Character.isLetter(c)?(char)((c+shift-base)%26+base):c);
  }return out.toString();
 }
 static String field(String s,boolean seal)throws Exception{
  if(s.isEmpty())return s;
  byte[] key=Arrays.copyOf(utf("Diablo2105AZW8Es"),32);
  byte[] raw=seal?new byte[16]:Base64.getUrlDecoder().decode(s);
  Cipher c=Cipher.getInstance("AES/CBC/PKCS5Padding");
  c.init(seal?1:2,new SecretKeySpec(key,"AES"),new IvParameterSpec(Arrays.copyOf(raw,16)));
  if(!seal)return rotate(new String(c.doFinal(Arrays.copyOfRange(raw,16,raw.length)),StandardCharsets.UTF_8),21);
  byte[] encrypted=c.doFinal(utf(rotate(s,5)));byte[] all=Arrays.copyOf(raw,16+encrypted.length);
  System.arraycopy(encrypted,0,all,16,encrypted.length);
  return Base64.getUrlEncoder().withoutPadding().encodeToString(all);
 }
 public static void main(String[] args)throws Exception{
  BufferedReader reader=new BufferedReader(new InputStreamReader(System.in,StandardCharsets.UTF_8));String line;
  while((line=reader.readLine())!=null){String[] p=line.split("\t",-1);
   String s=new String(Base64.getDecoder().decode(p[1]),StandardCharsets.UTF_8);
   String out=p[0].equals("field")?field(s,false):p[0].equals("seal")?field(s,true):rotate(s,21);
   System.out.println(Base64.getEncoder().encodeToString(utf(out)));
  }
 }
}

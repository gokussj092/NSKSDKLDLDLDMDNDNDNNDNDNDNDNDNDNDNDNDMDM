// Independent JDK transcription of AbstractC2562yx.a, PW.a/b and G2.confpass.
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.*;
import javax.crypto.Cipher;
import javax.crypto.spec.*;
class megatunnel_oracle {
 static byte[] utf(String s){return s.getBytes(StandardCharsets.UTF_8);}
 static String apply(String op,String text)throws Exception{
  boolean seal=op.startsWith("seal-");boolean field=op.endsWith("field");
  if(field){byte[] raw=seal?utf(text):Base64.getDecoder().decode(text);byte[] key=utf("Abtcji");for(int i=0;i<raw.length;i++)raw[i]^=key[i%key.length];return seal?Base64.getEncoder().encodeToString(raw):new String(raw,StandardCharsets.UTF_8);}
  byte[] nonce=new byte[12],raw;
  if(seal){for(int i=0;i<12;i++)nonce[i]=(byte)i;raw=utf(text);}
  else{byte[] all=Base64.getDecoder().decode(text.strip());nonce=Arrays.copyOf(all,12);raw=Arrays.copyOfRange(all,12,all.length);}
  Cipher c=Cipher.getInstance("AES/GCM/NoPadding");c.init(seal?1:2,new SecretKeySpec(Arrays.copyOf(utf(">, java const v1"),32),"AES"),new GCMParameterSpec(128,nonce));
  byte[] out=c.doFinal(raw);if(!seal)return new String(out,StandardCharsets.UTF_8);
  var result=new ByteArrayOutputStream();result.write(nonce);result.write(out);return Base64.getEncoder().encodeToString(result.toByteArray());
 }
 public static void main(String[]args)throws Exception{
  var r=new BufferedReader(new InputStreamReader(System.in,StandardCharsets.UTF_8));String line;
  while((line=r.readLine())!=null){String[]p=line.split("\t",2);String s=new String(Base64.getDecoder().decode(p[1]),StandardCharsets.UTF_8);System.out.println(Base64.getEncoder().encodeToString(utf(apply(p[0],s))));}
 }
}

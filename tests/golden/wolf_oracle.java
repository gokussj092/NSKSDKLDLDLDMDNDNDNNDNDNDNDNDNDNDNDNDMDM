// Independent JCA normalization of build 13's two native AES-GCM functions.
// Stdin: enc/dec TAB base64(raw key) TAB base64(nonce || plaintext), or ciphertext.
import java.io.*;
import java.util.*;
import java.nio.charset.StandardCharsets;
import javax.crypto.Cipher;
import javax.crypto.spec.*;
class WolfOracle {
 public static void main(String[] args)throws Exception {
  var reader=new BufferedReader(new InputStreamReader(System.in,StandardCharsets.UTF_8));
  for(String line;(line=reader.readLine())!=null;){
   String[] p=line.split("\t",-1);
   byte[] key=Base64.getDecoder().decode(p[1]),data=Base64.getDecoder().decode(p[2]);
   Cipher c=Cipher.getInstance("AES/GCM/NoPadding");
   boolean enc=p[0].equals("enc");
   if(!enc&&!p[0].equals("dec"))throw new IllegalArgumentException();
   c.init(enc?Cipher.ENCRYPT_MODE:Cipher.DECRYPT_MODE,new SecretKeySpec(key,"AES"),new GCMParameterSpec(128,Arrays.copyOf(data,12)));
   byte[] out=c.doFinal(Arrays.copyOfRange(data,12,data.length));
   if(enc){byte[] packed=Arrays.copyOf(data,12+out.length);System.arraycopy(out,0,packed,12,out.length);out=packed;}
   System.out.println(Base64.getEncoder().encodeToString(out));
  }
 }
}

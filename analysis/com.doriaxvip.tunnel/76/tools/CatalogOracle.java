import java.io.*;import java.nio.charset.StandardCharsets;import java.security.*;import java.util.*;import javax.crypto.*;import javax.crypto.spec.*;
/** Independent JCA; encryption modes generate fictional tests only; Genis build76 ROT4/ROT22. */
class CatalogOracle {
 static byte[] b64(String s,boolean url){s=s.replaceAll("[\\t\\r\\n ]","");return (url?Base64.getUrlDecoder():Base64.getDecoder()).decode(s);}
 static byte[] cbc(boolean enc,byte[]key,byte[]iv,byte[]data)throws Exception{Cipher c=Cipher.getInstance("AES/CBC/PKCS5Padding");c.init(enc?1:2,new SecretKeySpec(key,"AES"),new IvParameterSpec(iv));return c.doFinal(data);}
 static byte[] material(byte[]password,byte[]salt)throws Exception{var out=new ByteArrayOutputStream();byte[]prior=new byte[0];while(out.size()<48){var md=MessageDigest.getInstance("MD5");md.update(prior);md.update(password);prior=md.digest(salt);out.write(prior);}return out.toByteArray();}
 static String rotate(String s,int n){var out=new StringBuilder();for(char c:s.toCharArray()){if(Character.isLetter(c)){int start=Character.isUpperCase(c)?65:97;c=(char)((c+n-start)%26+start);}out.append(c);}return out.toString();}
 static byte[] process(String mode,byte[]password,byte[]data)throws Exception{
  if(mode.equals("O")){byte[]raw=b64(new String(data,StandardCharsets.US_ASCII),false);if(raw.length<32||!Arrays.equals(Arrays.copyOf(raw,8),"WakkoDev".getBytes(StandardCharsets.US_ASCII)))throw new IllegalArgumentException("Envelope");byte[]k=material(password,Arrays.copyOfRange(raw,8,16));return cbc(false,Arrays.copyOf(k,32),Arrays.copyOfRange(k,32,48),Arrays.copyOfRange(raw,16,raw.length));}
  if(mode.equals("F")){if(data.length==0)return data;byte[]raw=b64(new String(data,StandardCharsets.US_ASCII),true);byte[]clear=cbc(false,Arrays.copyOf(password,32),Arrays.copyOf(raw,16),Arrays.copyOfRange(raw,16,raw.length));return rotate(new String(clear,StandardCharsets.UTF_8),22).getBytes(StandardCharsets.UTF_8);}
  if(mode.equals("E")){byte[]salt="FAKE076!".getBytes(StandardCharsets.US_ASCII),k=material(password,salt);var out=new ByteArrayOutputStream();out.write("WakkoDev".getBytes(StandardCharsets.US_ASCII));out.write(salt);out.write(cbc(true,Arrays.copyOf(k,32),Arrays.copyOfRange(k,32,48),data));return Base64.getEncoder().encode(out.toByteArray());}
  if(mode.equals("G")){if(data.length==0)return data;byte[]iv=Arrays.copyOf(MessageDigest.getInstance("SHA-256").digest(data),16);var out=new ByteArrayOutputStream();out.write(iv);out.write(cbc(true,Arrays.copyOf(password,32),iv,rotate(new String(data,StandardCharsets.UTF_8),4).getBytes(StandardCharsets.UTF_8)));return Base64.getUrlEncoder().withoutPadding().encode(out.toByteArray());}
  throw new IllegalArgumentException("Mode");
 }
 public static void main(String[]args)throws Exception{var in=new BufferedReader(new InputStreamReader(System.in,StandardCharsets.UTF_8));String l;while((l=in.readLine())!=null){String[]s=l.split("\\t",-1);if(s.length!=3)throw new IllegalArgumentException("Input");System.out.println(Base64.getEncoder().encodeToString(process(s[0],Base64.getDecoder().decode(s[1]),Base64.getDecoder().decode(s[2]))));}}
}

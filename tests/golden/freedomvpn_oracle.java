// JDK reference from build-125 Ri/P5/CU, independent of the Python decoder.
import java.io.*;
import java.nio.*;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.*;
import javax.crypto.Cipher;
import javax.crypto.spec.*;
class freedomvpn_oracle {
 static final int DELTA=-170877363;
 static final String ALPHABET=":;<=>?!\"#$%&'()*";
 static final Map<String,String> KEYS=Map.of("payload","D7FoVFa7UrpkAuc03rQc","user","e6iQG0hiMfZWO8aOmLJY","obfs","cNEi7mEOyQyxRX5A275J","host","eXjaA5SFxj5vr4t1sjql");
 static int mix(int s,int y,int z,int p,int e,int[]k){return ((z>>>5^y<<2)+(y>>>3^z<<4))^((s^y)+(k[(p&3)^e]^z));}
 static byte[] xx(byte[] input,String password,boolean seal){
  int n=(input.length+3)/4+(seal?1:0);int[]v=new int[n],k=new int[4];byte[]key=Arrays.copyOf(password.getBytes(StandardCharsets.UTF_8),16);
  for(int i=0;i<input.length;i++)v[i>>>2]|=(input[i]&255)<<((i&3)*8);
  for(int i=0;i<16;i++)k[i>>>2]|=(key[i]&255)<<((i&3)*8);
  int rounds=6+52/n;
  if(seal){v[n-1]=input.length;int sum=0,z=v[n-1];for(int q=0;q<rounds;q++){sum+=DELTA;int e=sum>>>2&3;for(int p=0;p<n-1;p++){v[p]+=mix(sum,v[p+1],z,p,e,k);z=v[p];}v[n-1]+=mix(sum,v[0],z,n-1,e,k);z=v[n-1];}}
  else{int sum=rounds*DELTA,y=v[0];for(int q=0;q<rounds;q++){int e=sum>>>2&3;for(int p=n-1;p>0;p--){v[p]-=mix(sum,y,v[p-1],p,e,k);y=v[p];}v[0]-=mix(sum,y,v[n-1],0,e,k);y=v[0];sum-=DELTA;}}
  ByteBuffer out=ByteBuffer.allocate(n*4).order(ByteOrder.LITTLE_ENDIAN);for(int x:v)out.putInt(x);
  if(seal)return out.array();int size=v[n-1];if(size<4*n-7||size>4*n-4)throw new IllegalArgumentException("length");return Arrays.copyOf(out.array(),size);
 }
 static String rotate(String s,int amount){StringBuilder out=new StringBuilder();for(char c:s.toCharArray()){if(Character.isLetter(c)){int a=Character.isUpperCase(c)?65:97;c=(char)(((c+amount-a)%26)+a);}out.append(c);}return out.toString();}
 static byte[] b64(String s){return Base64.getDecoder().decode(s.replaceAll("\\s", ""));}
 static String b64(byte[] b){return Base64.getEncoder().encodeToString(b);}
 static String fieldKey(String name){return switch(name){case "Payload","SNI"->"payload";case "udpserver"->"user";case "udpobfs","ServerPass"->"obfs";default->"host";};}
 static String apply(String op,String value)throws Exception{
  boolean seal=op.startsWith("seal-");String name=seal?op.substring(5):op;
  if(name.equals("catalog")){byte[]out=xx(seal?value.getBytes(StandardCharsets.UTF_8):b64(value),"FreedomVPN525",seal);return seal?b64(out):new String(out,StandardCharsets.UTF_8);}
  if(value.isEmpty())return value;if(seal)value=rotate(value,1);
  byte[]out;
  if(name.equals("ServerUser"))out=xx(seal?value.getBytes(StandardCharsets.UTF_8):b64(value),KEYS.get("user"),seal);
  else{
   boolean ecb=name.equals("ServerIP");String pass=KEYS.get(fieldKey(name));byte[]key;
   if(ecb)key=Arrays.copyOf(pass.getBytes(StandardCharsets.UTF_8),16);
   else{StringBuilder hex=new StringBuilder();for(byte x:pass.getBytes(StandardCharsets.UTF_8))hex.append(String.format("%02X",x&255));key=MessageDigest.getInstance("SHA-256").digest(hex.toString().getBytes(StandardCharsets.UTF_8));}
   Cipher c=Cipher.getInstance(ecb?"AES/ECB/PKCS5Padding":"AES/CBC/PKCS5Padding");
   if(ecb)c.init(seal?1:2,new SecretKeySpec(key,"AES"));else c.init(seal?1:2,new SecretKeySpec(key,"AES"),new IvParameterSpec(new byte[16]));
   if(seal)out=c.doFinal(value.getBytes(StandardCharsets.UTF_8));
   else if(ecb)out=c.doFinal(b64(value));else{byte[]raw=new byte[value.length()/2];for(int i=0;i<raw.length;i++)raw[i]=(byte)(ALPHABET.indexOf(value.charAt(2*i))*16+ALPHABET.indexOf(value.charAt(2*i+1)));out=c.doFinal(Base64.getDecoder().decode(raw));}
  }
  if(!seal)return rotate(new String(out,StandardCharsets.UTF_8),25);
  String encoded=b64(out);if(name.equals("ServerIP")||name.equals("ServerUser"))return encoded;
  StringBuilder s=new StringBuilder();for(byte x:encoded.getBytes(StandardCharsets.US_ASCII))s.append(ALPHABET.charAt((x&255)>>>4)).append(ALPHABET.charAt(x&15));return s.toString();
 }
 public static void main(String[]args)throws Exception{BufferedReader r=new BufferedReader(new InputStreamReader(System.in,StandardCharsets.UTF_8));String line;while((line=r.readLine())!=null){String[]p=line.split("\t",2);System.out.println(b64(apply(p[0],new String(b64(p[1]),StandardCharsets.UTF_8)).getBytes(StandardCharsets.UTF_8)));}}
}

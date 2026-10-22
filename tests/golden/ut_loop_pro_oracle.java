import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.*;
import java.util.*;
import javax.crypto.*;
import javax.crypto.spec.*;

/** Independent JCA reference transcribed from APK util.r/c/n/d. Synthetic data only. */
class ut_loop_pro_oracle {
 static final Base64.Decoder B=Base64.getDecoder();
 static byte[] sha(byte[] x)throws Exception{return MessageDigest.getInstance("SHA-256").digest(x);}
 static byte[] key()throws Exception{
  byte[] a={(byte)-113,(byte)-125,(byte)-73,87,18,(byte)-122,107,(byte)-107,31,(byte)-12,(byte)-14,(byte)-8,127,61,(byte)-108,116,(byte)-22,67,(byte)-8,1,30,69,20,(byte)-113,(byte)-54,(byte)-106,(byte)-20,21,(byte)-3,57,(byte)-55,101};
  byte[] d=sha("uch3-pr0-0ta-scheme-v2".getBytes(StandardCharsets.UTF_8));
  for(int i=0;i<a.length;i++)a[i]^=d[i];return a;
 }
 static byte[] bannerKey(int slot)throws Exception{
  String[] fingerprints={"FC692B18C1E532FDA8B4CF485AA26355C006B3DC4442BF228684209CDB58A1D6","4102A213C55BC96C97B3451679831D392AB7BABD6A60B4AB2B6A5897A69EE83F"};
  String[] masks={"AcCXGRWjhbp85ER6z4BFwrXQWUg6uA4eIW7THGweEqa7M2mCGTTY8anVGHA=","h/STJJ0eoQaWIV4Z9qRnRP6EES7AEyckzt+GmGp1i/QlGVk24DlOJLmKmp8="};
  byte[] digest=HexFormat.of().parseHex(fingerprints[slot]),out=B.decode(masks[slot]);
  for(int offset=0,counter=0;offset<out.length;counter++){
   MessageDigest h=MessageDigest.getInstance("SHA-256");h.update(digest);h.update((byte)counter);
   byte[] block=h.digest();for(int j=0;j<block.length&&offset<out.length;j++,offset++)out[offset]^=block[j];
  }return B.decode(out);
 }
 static byte[] gcm(byte[] raw,byte[] k,boolean seal,boolean banner)throws Exception{
  Cipher c=Cipher.getInstance("AES/GCM/NoPadding");byte[] nonce;
  if(seal){nonce=HexFormat.of().parseHex("000102030405060708090a0b");}
  else{nonce=Arrays.copyOf(raw,12);raw=Arrays.copyOfRange(raw,12,raw.length);}
  c.init(seal?Cipher.ENCRYPT_MODE:Cipher.DECRYPT_MODE,new SecretKeySpec(k,"AES"),new GCMParameterSpec(128,nonce));
  if(banner)c.updateAAD("utloop-banner-v1".getBytes(StandardCharsets.UTF_8));
  byte[] value=c.doFinal(raw);
  if(!seal)return value;
  byte[] out=Arrays.copyOf(nonce,nonce.length+value.length);System.arraycopy(value,0,out,12,value.length);return out;
 }
 static int mx(int sum,int y,int z,int p,int e,int[] k){return ((z>>>5^y<<2)+(y>>>3^z<<4))^((sum^y)+(k[(p&3)^e]^z));}
 static byte[] tea(byte[] raw,boolean seal){
  byte[] key=Arrays.copyOf("uchehacks".getBytes(StandardCharsets.UTF_8),16);int[] k=new int[4];for(int i=0;i<16;i++)k[i>>>2]|=(key[i]&255)<<((i&3)<<3);
  int count=(raw.length+3)/4;int[] v=new int[count+(seal?1:0)];if(seal)v[count]=raw.length;
  for(int i=0;i<raw.length;i++)v[i>>>2]|=(raw[i]&255)<<((i&3)<<3);
  int n=v.length,delta=-1704280,rounds=6+52/n;
  if(seal){int z=v[n-1],sum=0;for(int q=0;q<rounds;q++){sum+=delta;int e=sum>>>2&3;for(int p=0;p<n-1;p++)z=v[p]+=mx(sum,v[p+1],z,p,e,k);z=v[n-1]+=mx(sum,v[0],z,n-1,e,k);}}
  else{int y=v[0],sum=rounds*delta;for(int q=0;q<rounds;q++){int e=sum>>>2&3;for(int p=n-1;p>0;p--)y=v[p]-=mx(sum,y,v[p-1],p,e,k);y=v[0]-=mx(sum,y,v[n-1],0,e,k);sum-=delta;}}
  int size=seal?n*4:v[n-1];if(size<0||size>n*4)throw new IllegalArgumentException("length");
  byte[] out=new byte[size];for(int i=0;i<size;i++)out[i]=(byte)(v[i>>>2]>>>((i&3)<<3));return out;
 }
 public static void main(String[] args)throws Exception{
  String encoded=new BufferedReader(new InputStreamReader(System.in,StandardCharsets.UTF_8)).readLine();byte[] raw=B.decode(encoded);
  String mode=args[0];byte[] out;
  if(mode.equals("sign")){
   SecureRandom random=SecureRandom.getInstance("SHA1PRNG");random.setSeed("SP-DECODE UT Loop SYNTHETIC TEST SIGNER ONLY".getBytes(StandardCharsets.UTF_8));
   KeyPairGenerator g=KeyPairGenerator.getInstance("RSA");g.initialize(2048,random);KeyPair pair=g.generateKeyPair();
   Signature s=Signature.getInstance("SHA256withRSA");s.initSign(pair.getPrivate());s.update(raw);
   System.out.println(Base64.getEncoder().encodeToString(pair.getPublic().getEncoded()));out=s.sign();
  }else if(mode.startsWith("banner-")){out=gcm(raw,bannerKey(Integer.parseInt(args[1])),mode.equals("banner-seal"),true);}
  else if(mode.startsWith("legacy-")){out=tea(raw,mode.equals("legacy-seal"));}
  else{out=gcm(raw,key(),mode.equals("seal"),false);}
  System.out.println(Base64.getEncoder().encodeToString(out));
 }
}

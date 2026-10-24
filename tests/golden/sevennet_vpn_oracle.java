import java.io.*;
import java.nio.*;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.*;
import javax.crypto.*;
import javax.crypto.spec.*;

/** Independent JCA + Threefish/XXTEA reference for authorized build-56 inputs. */
class sevennet_vpn_oracle {
 static byte[] hex(String s){return HexFormat.of().parseHex(s);}
 static byte[] seed=hex("deb72221be4652c347f930e85adc29970ccd499cf42e361b3d6b14918912bf3b");
 static byte[] salt=hex("70ed508428ff7b5bcde0bcdd3b9474932ab1cabc5ff6870e6e584b4fa7925f55");
 static byte[] iv=hex("2d2f3112a271edbba9a41ad58a3a99bf"), k16,h16,h32,p32;
 static final int[][] ROT={{14,16},{52,57},{23,40},{5,37},{25,33},{46,12},{58,22},{32,32}};
 static byte[] hmac(byte[] key,byte[] input)throws Exception{Mac m=Mac.getInstance("HmacSHA256");m.init(new SecretKeySpec(key,"HmacSHA256"));return m.doFinal(input);}
 static byte[] hkdf(byte[] s,int n)throws Exception{byte[] prk=hmac(s,seed);return Arrays.copyOf(hmac(prk,new byte[]{1}),n);}
 static byte[] pbkdf()throws Exception{
  byte[] input=Arrays.copyOf(salt,salt.length+4);input[input.length-1]=1;
  byte[] u=hmac(seed,input),out=u.clone();Mac m=Mac.getInstance("HmacSHA256");m.init(new SecretKeySpec(seed,"HmacSHA256"));
  for(int i=1;i<100000;i++){u=m.doFinal(u);for(int j=0;j<32;j++)out[j]^=u[j];}return out;
 }
 static void init()throws Exception{k16=Arrays.copyOf(MessageDigest.getInstance("SHA-256").digest(seed),16);h16=hkdf(Arrays.copyOf(salt,16),16);h32=hkdf(salt,32);p32=pbkdf();}
 static byte[] cbc(byte[] data,byte[] key,byte[] nonce,boolean seal)throws Exception{Cipher c=Cipher.getInstance("AES/CBC/PKCS5Padding");c.init(seal?Cipher.ENCRYPT_MODE:Cipher.DECRYPT_MODE,new SecretKeySpec(key,"AES"),new IvParameterSpec(nonce));return c.doFinal(data);}
 static int mx(int sum,int y,int z,int p,int e,int[] k){return ((z>>>5^y<<2)+(y>>>3^z<<4))^((sum^y)+(k[(p&3)^e]^z));}
 static byte[] tea(byte[] raw,byte[] material,boolean seal){
  byte[] key=Arrays.copyOf(material,16);for(int i=0;i<15;i++)if(key[i]==0){Arrays.fill(key,i+1,16,(byte)0);break;}
  int[] k=new int[4];for(int i=0;i<16;i++)k[i>>>2]|=(key[i]&255)<<((i&3)<<3);
  if(!seal&&(raw.length<8||raw.length%4!=0))throw new IllegalArgumentException("XXTEA length");
  int count=(raw.length+3)/4;int[] v=new int[count+(seal?1:0)];if(seal)v[count]=raw.length;
  for(int i=0;i<raw.length;i++)v[i>>>2]|=(raw[i]&255)<<((i&3)<<3);
  int n=v.length,delta=2052510689,rounds=6+52/n;
  if(seal){int z=v[n-1],sum=0;for(int q=0;q<rounds;q++){sum+=delta;int e=sum>>>2&3;for(int p=0;p<n-1;p++)z=v[p]+=mx(sum,v[p+1],z,p,e,k);z=v[n-1]+=mx(sum,v[0],z,n-1,e,k);}}
  else{int y=v[0],sum=rounds*delta;for(int q=0;q<rounds;q++){int e=sum>>>2&3;for(int p=n-1;p>0;p--)y=v[p]-=mx(sum,y,v[p-1],p,e,k);y=v[0]-=mx(sum,y,v[n-1],0,e,k);sum-=delta;}}
  int size=seal?n*4:v[n-1];if(!seal&&(size<n*4-7||size>n*4-4))throw new IllegalArgumentException("XXTEA size");
  byte[] out=new byte[size];for(int i=0;i<size;i++)out[i]=(byte)(v[i>>>2]>>>((i&3)<<3));return out;
 }
 static long[][] sub(long t0,long t1){
  long[] k=new long[5];ByteBuffer b=ByteBuffer.wrap(h32).order(ByteOrder.LITTLE_ENDIAN);k[4]=0x1bd11bdaa9fc1a22L;
  for(int i=0;i<4;i++){k[i]=b.getLong();k[4]^=k[i];}
  long[] t={t0,t1,t0^t1};long[][] s=new long[19][4];
  for(int i=0;i<19;i++){s[i][0]=k[i%5];s[i][1]=k[(i+1)%5]+t[i%3];s[i][2]=k[(i+2)%5]+t[(i+1)%3];s[i][3]=k[(i+3)%5]+i;}return s;
 }
 static byte[] fish(byte[] raw,boolean seal){
  if(raw.length%32!=0)throw new IllegalArgumentException("Threefish length");byte[] out=new byte[raw.length];
  for(int offset=0;offset<raw.length;offset+=32){
   ByteBuffer b=ByteBuffer.wrap(raw,offset,32).order(ByteOrder.LITTLE_ENDIAN);long[] x={b.getLong(),b.getLong(),b.getLong(),b.getLong()};
   long[][] s=sub(offset/32,0);
   if(seal){
    for(int j=0;j<4;j++)x[j]+=s[0][j];
    for(int round=0;round<72;round++){
     int[] r=ROT[round%8];for(int p=0;p<4;p+=2){x[p]+=x[p+1];x[p+1]=Long.rotateLeft(x[p+1],r[p/2])^x[p];}
     long tmp=x[1];x[1]=x[3];x[3]=tmp;
     if(round%4==3)for(int j=0;j<4;j++)x[j]+=s[round/4+1][j];
    }
   }else{
    for(int round=71;round>=0;round--){
     if(round%4==3)for(int j=0;j<4;j++)x[j]-=s[round/4+1][j];
     long tmp=x[1];x[1]=x[3];x[3]=tmp;
     int[] r=ROT[round%8];for(int p=0;p<4;p+=2){x[p+1]=Long.rotateRight(x[p]^x[p+1],r[p/2]);x[p]-=x[p+1];}
    }for(int j=0;j<4;j++)x[j]-=s[0][j];
   }
   b=ByteBuffer.wrap(out,offset,32).order(ByteOrder.LITTLE_ENDIAN);for(long v:x)b.putLong(v);
  }return out;
 }
 static byte[] decode(int mode,byte[] input)throws Exception{
  String text=new String(input,StandardCharsets.UTF_8);
  if(mode==0){byte[] out=tea(cbc(Base64.getMimeDecoder().decode(text),k16,iv,false),k16,false);for(int i=0;i<out.length;i++)out[i]-=2;return out;}
  if(mode==1){byte[] raw=fish(Base64.getMimeDecoder().decode(text),false);int end=raw.length;while(end>0&&raw[end-1]==0)end--;end=(end+15)/16*16;return cbc(Arrays.copyOf(raw,end),h16,iv,false);}
  if(mode==2){byte[] raw=Base64.getMimeDecoder().decode(text);raw=tea(raw,p32,false);return cbc(Arrays.copyOfRange(raw,16,raw.length),p32,Arrays.copyOf(raw,16),false);}
  if(mode==3)return fish(input,false);
  if(mode==4)return tea(input,k16,false);
  if(mode==6)return tea(input,p32,false);
  if(mode==10){byte[] shifted=input.clone();for(int i=0;i<shifted.length;i++)shifted[i]+=2;return Base64.getEncoder().encode(cbc(tea(shifted,k16,true),k16,iv,true));}
  if(mode==11){byte[] raw=cbc(input,h16,iv,true);raw=Arrays.copyOf(raw,(raw.length+31)/32*32);return Base64.getEncoder().encode(fish(raw,true));}
  if(mode==12){byte[] nonce=hex("000102030405060708090a0b0c0d0e0f"),ct=cbc(input,p32,nonce,true);byte[] raw=Arrays.copyOf(nonce,16+ct.length);System.arraycopy(ct,0,raw,16,ct.length);return Base64.getEncoder().encode(tea(raw,p32,true));}
  throw new IllegalArgumentException("mode");
 }
 public static void main(String[]args)throws Exception{
  init();BufferedReader reader=new BufferedReader(new InputStreamReader(System.in,StandardCharsets.UTF_8));String line;
  while((line=reader.readLine())!=null){String[] p=line.split("\t",2);byte[] out=decode(Integer.parseInt(p[0]),Base64.getDecoder().decode(p[1]));System.out.println(Base64.getEncoder().encodeToString(out));}
 }
}

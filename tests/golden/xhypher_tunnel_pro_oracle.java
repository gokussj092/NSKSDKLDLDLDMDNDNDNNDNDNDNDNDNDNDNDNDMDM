import java.io.*;
import java.nio.*;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.*;
import javax.crypto.*;
import javax.crypto.spec.*;

/** Independent JCA + Threefish/XXTEA reference for authorized build-43 inputs. */
class xhypher_tunnel_pro_oracle {
 static byte[] hex(String s){return HexFormat.of().parseHex(s);}
 static byte[] seed=hex("be97b5612d7c13787b64e2cb373d3d2288119623aaa0ca8dfeb0c7bcd3a8df85");
 static byte[] salt=hex("2f09b4a555853a46b5057f6b9e50e0322e76f566487623c70119bceb12178e83");
 static byte[] iv=hex("0c0ca925cafd2438f985fc35e609807d"), k16,h16,h32,p32;
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
   long[][] s=sub(offset/32,offset/32*192);
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
 static byte[] invisible(String text){
  ByteArrayOutputStream out=new ByteArrayOutputStream();int v=0,bits=0;
  for(char c:text.toCharArray()){
   if(c=='\u200d')continue;if(c!='\u200b'&&c!='\u200c')throw new IllegalArgumentException("carrier");
   v=v*2+(c=='\u200c'?1:0);if(++bits==8){out.write(((v&0xaa)>>>1|(v&0x55)<<1)^0x5a);bits=v=0;}
  }if(bits!=0)throw new IllegalArgumentException("incomplete byte");return out.toByteArray();
 }
 static String invisibleEncode(byte[] raw){
  StringBuilder out=new StringBuilder();out.append('\u200d');
  for(byte b:raw){int x=(b&255)^0x5a;int v=(x&0xaa)>>>1|(x&0x55)<<1;for(int bit=7;bit>=0;bit--)out.append(((v>>>bit)&1)==0?'\u200b':'\u200c');}
  out.append('\u200d');return out.toString();
 }
 static byte[] decode(int mode,byte[] input)throws Exception{
  String text=new String(input,StandardCharsets.UTF_8);
  if(mode==0)return tea(cbc(Base64.getMimeDecoder().decode(text),k16,iv,false),k16,false);
  if(mode==1){byte[] raw=fish(Base64.getMimeDecoder().decode(text),false);int end=raw.length;while(end>0&&raw[end-1]==0)end--;end=(end+15)/16*16;return cbc(Arrays.copyOf(raw,end),h16,iv,false);}
  if(mode==2){byte[] raw=text.indexOf('\u200b')>=0?invisible(text):Base64.getMimeDecoder().decode(text);raw=tea(raw,p32,false);return cbc(Arrays.copyOfRange(raw,16,raw.length),p32,Arrays.copyOf(raw,16),false);}
  if(mode==3)return fish(input,false);
  if(mode==4)return tea(input,k16,false);
  if(mode==5)return invisible(text);
  if(mode==10)return Base64.getEncoder().encode(cbc(tea(input,k16,true),k16,iv,true));
  if(mode==11){byte[] raw=cbc(input,h16,iv,true);raw=Arrays.copyOf(raw,(raw.length+31)/32*32);return Base64.getEncoder().encode(fish(raw,true));}
  if(mode==12){byte[] nonce=hex("000102030405060708090a0b0c0d0e0f"),ct=cbc(input,p32,nonce,true);byte[] raw=Arrays.copyOf(nonce,16+ct.length);System.arraycopy(ct,0,raw,16,ct.length);return invisibleEncode(tea(raw,p32,true)).getBytes(StandardCharsets.UTF_8);}
  throw new IllegalArgumentException("mode");
 }
 public static void main(String[]args)throws Exception{
  init();BufferedReader reader=new BufferedReader(new InputStreamReader(System.in,StandardCharsets.UTF_8));String line;
  while((line=reader.readLine())!=null){String[] p=line.split("\t",2);byte[] out=decode(Integer.parseInt(p[0]),Base64.getDecoder().decode(p[1]));System.out.println(Base64.getEncoder().encodeToString(out));}
 }
}

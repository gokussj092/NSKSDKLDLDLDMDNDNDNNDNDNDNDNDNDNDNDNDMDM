import java.io.*;
import java.util.*;
import java.nio.charset.StandardCharsets;
/** Independent Java transcription of APK iL and r4.T/D; synthetic stdin only. */
class zig_oracle {
 static final int DELTA=772515655;
 static final int[] KEY={0x39363634,0,0,0};
 static int mx(int sum,int y,int z,int p,int e){return ((z>>>5 ^ y<<2)+(y>>>3 ^ z<<4))^((sum^y)+(KEY[(p&3)^e]^z));}
 static byte[] crypt(byte[] input,boolean seal){
  if(input.length==0)return input;
  int n=(input.length+3)/4+(seal?1:0);int[] v=new int[n];
  for(int i=0;i<input.length;i++)v[i>>>2]|=(input[i]&255)<<((i&3)*8);
  if(seal)v[n-1]=input.length;
  int rounds=6+52/n;
  if(seal){int sum=0,z=v[n-1];for(int q=0;q<rounds;q++){
   sum+=DELTA;int e=(sum>>>2)&3;int p;
   for(p=0;p<n-1;p++)z=v[p]+=mx(sum,v[p+1],z,p,e);
   z=v[n-1]+=mx(sum,v[0],z,p,e);
  }}else{int sum=rounds*DELTA,y=v[0];while(sum!=0){int e=(sum>>>2)&3;int p;
   for(p=n-1;p>0;p--)y=v[p]-=mx(sum,y,v[p-1],p,e);
   y=v[0]-=mx(sum,y,v[n-1],0,e);sum-=DELTA;
  }}
  int size=n*4;if(!seal){size=v[n-1];if(size<n*4-7||size>n*4-4)throw new IllegalArgumentException("length");}
  byte[] out=new byte[size];for(int i=0;i<size;i++)out[i]=(byte)(v[i>>>2]>>>((i&3)*8));return out;
 }
 static String transform(String s,boolean seal){
  if(seal){char[] a=s.toCharArray();for(int i=0;i<a.length;i++)a[i]=(char)(a[i]+4669);for(int i=0;i<a.length;i++)a[i]=(char)(a[i]+4669);
   return Base64.getEncoder().encodeToString(crypt(new String(a).getBytes(StandardCharsets.UTF_8),true));}
  String s2=new String(crypt(Base64.getMimeDecoder().decode(s),false),StandardCharsets.UTF_8);char[] a=s2.toCharArray();
  for(int i=0;i<a.length;i++)a[i]=(char)(a[i]-4669);for(int i=0;i<a.length;i++)a[i]=(char)(a[i]-4669);return new String(a);
 }
 public static void main(String[] a)throws Exception{
  var r=new BufferedReader(new InputStreamReader(System.in,StandardCharsets.UTF_8));String line;
  while((line=r.readLine())!=null){String[] p=line.split("\t",2);String input=new String(Base64.getDecoder().decode(p[1]),StandardCharsets.UTF_8);
   System.out.println(Base64.getEncoder().encodeToString(transform(input,p[0].equals("E")).getBytes(StandardCharsets.UTF_8)));}
 }
}

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.*;
/** Offline arithmetic transcription of P60/O60; no APK/JNI execution. */
class StringOracle {
 public static void main(String[] args)throws Exception {
  var in=new BufferedReader(new InputStreamReader(System.in,StandardCharsets.UTF_8));String line;
  while((line=in.readLine())!=null){
   String[] fields=line.split(",");long[] v=new long[fields.length];
   for(int i=0;i<v.length;i++)v[i]=Long.parseLong(fields[i].trim());
   Random random=new Random(v[0]);byte[] out=new byte[(v.length-1)*8];
   for(int i=1;i<v.length;i++){long word=v[i]^random.nextLong();
    for(int j=0;j<8;j++){out[(i-1)*8+j]=(byte)word;word>>=8;}}
   int n=out.length;while(n>0&&out[n-1]==0)n--;
   System.out.println(Base64.getEncoder().encodeToString(Arrays.copyOf(out,n)));
  }
 }
}

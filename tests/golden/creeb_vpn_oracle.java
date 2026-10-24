import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.*;

// Independent JDK transcript of ge6.a/B/C/f/g; fixed sh0.b/c only.
// stdin: Cenc|Cdec|Senc|Sdec TAB Base64(input); stdout Base64(output).
class CreebVpnOracle {
    static int mix(int sum,int y,int z,int p,int e,int[] key) {
        return (((z>>>5)^(y<<2))+((y>>>3)^(z<<4)))^((sum^y)+(key[(p&3)^e]^z));
    }
    static byte[] tea(byte[] input,byte[] kb,boolean encrypt) {
        if(input.length==0)return input;
        int n=encrypt?(input.length+3)/4+1:input.length/4;
        if(n<2 || !encrypt && input.length%4!=0)throw new IllegalArgumentException();
        int[] v=new int[n],key=new int[4];kb=Arrays.copyOf(kb,16);
        for(int i=0;i<16;i++)key[i/4]|=(kb[i]&255)<<((i%4)*8);
        for(int i=0;i<input.length;i++)v[i/4]|=(input[i]&255)<<((i%4)*8);
        int rounds=6+52/n,delta=-1703701580;
        if(encrypt){
            v[n-1]=input.length;int sum=0,z=v[n-1];
            for(int q=0;q<rounds;q++){
                sum+=delta;int e=(sum>>>2)&3,p;
                for(p=0;p<n-1;p++){v[p]+=mix(sum,v[p+1],z,p,e,key);z=v[p];}
                v[n-1]+=mix(sum,v[0],z,n-1,e,key);z=v[n-1];
            }
        }else{
            int sum=rounds*delta,y=v[0];
            for(int q=0;q<rounds;q++){
                int e=(sum>>>2)&3,p;
                for(p=n-1;p>0;p--){v[p]-=mix(sum,y,v[p-1],p,e,key);y=v[p];}
                v[0]-=mix(sum,y,v[n-1],0,e,key);y=v[0];sum-=delta;
            }
        }
        int length=encrypt?n*4:v[n-1];
        if(!encrypt && (length<input.length-7 || length>input.length-4))throw new IllegalArgumentException();
        byte[] result=new byte[length];
        for(int i=0;i<length;i++)result[i]=(byte)(v[i/4]>>>((i%4)*8));
        return result;
    }
    public static void main(String[] args)throws Exception {
        var reader=new BufferedReader(new InputStreamReader(System.in,StandardCharsets.UTF_8));String line;
        while((line=reader.readLine())!=null){
            String[] parts=line.split("\t",-1);String op=parts[0];
            if(!Set.of("Cenc","Cdec","Senc","Sdec").contains(op))throw new IllegalArgumentException();
            boolean enc=op.endsWith("enc");
            byte[] key=(op.startsWith("C")?"DEV_CREEB":"ᜀᜎᜊᜌᜁᜈᜂ").getBytes(StandardCharsets.UTF_8);
            byte[] input=Base64.getDecoder().decode(parts[1]);
            byte[] output=tea(enc?input:Base64.getMimeDecoder().decode(input),key,enc);
            System.out.println(Base64.getEncoder().encodeToString(enc?Base64.getEncoder().encode(output):output));
        }
    }
}

import java.io.*;
import java.nio.*;
import java.nio.charset.*;
import java.util.*;

// Independent Java transcription of NAMO build35 j44.m/n (not Python code).
class CatalogOracle {
    static final int DELTA=772515655;
    static int mx(int sum,int y,int z,int p,int e,int[] key) {
        return (((z>>>5)^(y<<2))+((y>>>3)^(z<<4)))^((sum^y)+(key[(p&3)^e]^z));
    }
    static byte[] transform(byte[] raw,byte[] key,boolean encrypt) {
        if(!encrypt&&(raw.length<8||raw.length%4!=0))throw new IllegalArgumentException("size");
        int count=encrypt?(raw.length+3)/4+1:raw.length/4;
        int[] v=new int[count],k=new int[4];
        ByteBuffer in=ByteBuffer.wrap(Arrays.copyOf(raw,count*4)).order(ByteOrder.LITTLE_ENDIAN);
        for(int i=0;i<count;i++)v[i]=in.getInt();
        in=ByteBuffer.wrap(Arrays.copyOf(key,16)).order(ByteOrder.LITTLE_ENDIAN);
        for(int i=0;i<4;i++)k[i]=in.getInt();
        int rounds=6+52/count;
        if(encrypt) {
            v[count-1]=raw.length;int sum=0,z=v[count-1];
            for(int r=0;r<rounds;r++) {
                sum+=DELTA;int e=(sum>>>2)&3;
                for(int p=0;p<count;p++){int y=v[(p+1)%count];v[p]+=mx(sum,y,z,p,e,k);z=v[p];}
            }
        } else {
            int sum=rounds*DELTA,y=v[0];
            while(sum!=0) {
                int e=(sum>>>2)&3;
                for(int p=count-1;p>0;p--){int z=v[p-1];v[p]-=mx(sum,y,z,p,e,k);y=v[p];}
                v[0]-=mx(sum,y,v[count-1],0,e,k);y=v[0];sum-=DELTA;
            }
        }
        int size=encrypt?count*4:v[count-1];
        if(!encrypt&&(size<(count-1)*4-3||size>(count-1)*4))throw new IllegalArgumentException("length");
        ByteBuffer out=ByteBuffer.allocate(count*4).order(ByteOrder.LITTLE_ENDIAN);
        for(int value:v)out.putInt(value);
        return Arrays.copyOf(out.array(),size);
    }
    public static void main(String[] args)throws Exception {
        var reader=new BufferedReader(new InputStreamReader(System.in,StandardCharsets.UTF_8));
        String line;
        while((line=reader.readLine())!=null) {
            String[] f=line.split("\t",-1);byte[] key=Base64.getDecoder().decode(f[1]);
            byte[] input=Base64.getDecoder().decode(f[2]);
            byte[] result;
            if(f[0].equals("E"))result=Base64.getEncoder().encode(transform(input,key,true));
            else if(f[0].equals("D")) {
                byte[] cipher=Base64.getMimeDecoder().decode(input);
                result=transform(cipher,key,false);
                StandardCharsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT).decode(ByteBuffer.wrap(result));
            } else throw new IllegalArgumentException("mode");
            System.out.println(Base64.getEncoder().encodeToString(result));
        }
    }
}

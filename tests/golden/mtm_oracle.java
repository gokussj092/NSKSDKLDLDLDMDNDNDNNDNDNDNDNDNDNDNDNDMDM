import java.nio.*;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.io.*;

// Independent Java int arithmetic for APK Sj.b/d (delta -1638454863).
class mtm_oracle {
    static final int DELTA = -1638454863;
    static int[] key() {
        ByteBuffer b=ByteBuffer.wrap(Arrays.copyOf("Princie!".getBytes(StandardCharsets.UTF_8),16)).order(ByteOrder.LITTLE_ENDIAN);
        return new int[]{b.getInt(),b.getInt(),b.getInt(),b.getInt()};
    }
    static int mx(int sum,int y,int z,int p,int e,int[] k) {
        return (((z>>>5)^(y<<2))+((y>>>3)^(z<<4)))^((sum^y)+(k[(p&3)^e]^z));
    }
    static byte[] seal(byte[] plain) {
        int n=(plain.length+3)/4+1;
        ByteBuffer b=ByteBuffer.allocate(n*4).order(ByteOrder.LITTLE_ENDIAN);
        b.put(plain);b.putInt((n-1)*4,plain.length);b.rewind();
        int[] v=new int[n],k=key();for(int i=0;i<n;i++)v[i]=b.getInt();
        int sum=0,z=v[n-1];
        for(int rounds=6+52/n;rounds>0;rounds--) {
            sum+=DELTA;int e=(sum>>>2)&3;
            for(int p=0;p<n-1;p++){v[p]+=mx(sum,v[p+1],z,p,e,k);z=v[p];}
            v[n-1]+=mx(sum,v[0],z,n-1,e,k);z=v[n-1];
        }
        b.rewind();for(int x:v)b.putInt(x);
        return Base64.getEncoder().encode(b.array());
    }
    static byte[] open(byte[] input) {
        byte[] raw=Base64.getMimeDecoder().decode(input);int n=raw.length/4;
        if(n<2||raw.length%4!=0)throw new IllegalArgumentException("size");
        ByteBuffer b=ByteBuffer.wrap(raw).order(ByteOrder.LITTLE_ENDIAN);
        int[] v=new int[n],k=key();for(int i=0;i<n;i++)v[i]=b.getInt();
        int sum=(6+52/n)*DELTA,y=v[0];
        while(sum!=0) {
            int e=(sum>>>2)&3;
            for(int p=n-1;p>0;p--){v[p]-=mx(sum,y,v[p-1],p,e,k);y=v[p];}
            v[0]-=mx(sum,y,v[n-1],0,e,k);y=v[0];sum-=DELTA;
        }
        int count=v[n-1],max=(n-1)*4;
        if(count<max-3||count>max)throw new IllegalArgumentException("length");
        b.rewind();for(int x:v)b.putInt(x);
        return Arrays.copyOf(b.array(),count);
    }
    public static void main(String[] args) throws Exception {
        if(args.length==1){System.out.write(open(java.nio.file.Files.readAllBytes(java.nio.file.Path.of(args[0]))));return;}
        BufferedReader r=new BufferedReader(new InputStreamReader(System.in,StandardCharsets.UTF_8));String line;
        while((line=r.readLine())!=null){String[] p=line.split("\t",2);byte[] data=Base64.getDecoder().decode(p[1]);
            System.out.println(Base64.getEncoder().encodeToString(p[0].equals("seal")?seal(data):open(data)));}
    }
}

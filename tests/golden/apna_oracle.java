import java.nio.*;
import java.nio.file.*;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.io.*;

// Independent Java implementation of Dalvik Bm and the recovered native XOR.
class apna_oracle {
    static byte[] catalog(byte[] input) {
        byte[] raw=Base64.getMimeDecoder().decode(input);
        int n=raw.length/4;
        if(n<2||raw.length%4!=0)throw new IllegalArgumentException("size");
        int[] values=new int[n],key=new int[4];
        ByteBuffer buffer=ByteBuffer.wrap(raw).order(ByteOrder.LITTLE_ENDIAN);
        for(int i=0;i<n;i++)values[i]=buffer.getInt();
        buffer=ByteBuffer.wrap(Arrays.copyOf("...|...".getBytes(StandardCharsets.UTF_8),16)).order(ByteOrder.LITTLE_ENDIAN);
        for(int i=0;i<4;i++)key[i]=buffer.getInt();
        int delta=0x9e5729b1,sum=(6+52/n)*delta,y=values[0];
        while(sum!=0) {
            int e=(sum>>>2)&3;
            for(int p=n-1;p>0;p--) {
                int z=values[p-1];
                values[p]-=(((z>>>5)^(y<<2))+((y>>>3)^(z<<4)))^((sum^y)+(key[(p&3)^e]^z));
                y=values[p];
            }
            int z=values[n-1];
            values[0]-=(((z>>>5)^(y<<2))+((y>>>3)^(z<<4)))^((sum^y)+(key[e]^z));
            y=values[0];sum-=delta;
        }
        int count=values[n-1],max=(n-1)*4;
        if(count<max-3||count>max)throw new IllegalArgumentException("length");
        ByteBuffer out=ByteBuffer.allocate(n*4).order(ByteOrder.LITTLE_ENDIAN);
        for(int v:values)out.putInt(v);
        return Arrays.copyOf(out.array(),count);
    }
    static String profile(String source) throws Exception {
        String text=source.strip();
        if(text.startsWith("apnavpn://"))text=text.substring(10);
        byte[] raw=HexFormat.of().parseHex(text),key="4%PdXch>fkP]".getBytes(StandardCharsets.US_ASCII);
        for(int i=0;i<raw.length;i++)raw[i]^=key[i%key.length];
        if(raw.length>65535)throw new IllegalArgumentException("test vector exceeds writeUTF limit");
        ByteArrayOutputStream b=new ByteArrayOutputStream();DataOutputStream output=new DataOutputStream(b);
        output.writeShort(raw.length);output.write(raw);
        return new DataInputStream(new ByteArrayInputStream(b.toByteArray())).readUTF();
    }
    public static void main(String[] args) throws Exception {
        byte[] raw=Files.readAllBytes(Path.of(args[1]));
        System.out.write(args[0].equals("catalog")?catalog(raw):profile(new String(raw,StandardCharsets.UTF_8)).getBytes(StandardCharsets.UTF_8));
    }
}

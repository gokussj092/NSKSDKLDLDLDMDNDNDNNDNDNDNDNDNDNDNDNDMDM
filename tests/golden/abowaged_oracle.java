import java.io.*;
import java.nio.*;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.*;
import javax.crypto.*;
import javax.crypto.spec.*;

// Independent JDK reference for AboWaged 1.0's Dalvik/JNI recipes.
// stdin: operation TAB Base64(bytes). stdout: Base64(result). Never log data.
class AboWagedOracle {
    static final byte[] IV = HexFormat.of().parseHex("0123456789abcdef1032547698badcfe");
    static final int DELTA = -1703701580;
    static byte[] hash(String text) throws Exception {
        return MessageDigest.getInstance("SHA-256").digest(text.getBytes(StandardCharsets.UTF_8));
    }
    static byte[] aes(byte[] data, byte[] key, byte[] iv, boolean cfb, boolean encrypt) throws Exception {
        Cipher c=Cipher.getInstance(cfb?"AES/CFB/NoPadding":"AES/CBC/PKCS5Padding");
        c.init(encrypt?Cipher.ENCRYPT_MODE:Cipher.DECRYPT_MODE,new SecretKeySpec(key,"AES"),new IvParameterSpec(iv));
        return c.doFinal(data);
    }
    static byte[] profileKey() throws Exception {
        byte[] text=aes(Base64.getDecoder().decode("lQ+t8x63PO1wN4B7vFjgfA=="),hash("C3sNbUKg92mKwhxQObxKpA=="),new byte[16],false,false);
        return MessageDigest.getInstance("SHA-256").digest(text);
    }
    static int mx(int sum,int y,int z,int p,int e,int[] k) {
        return (((z>>>5)^(y<<2))+((y>>>3)^(z<<4))) ^ ((sum^y)+(k[(p&3)^e]^z));
    }
    static byte[] tea(byte[] data,boolean encrypt) {
        int n=encrypt?(data.length+3)/4+1:data.length/4;
        if(n<2 || !encrypt && data.length%4!=0)throw new IllegalArgumentException();
        int[] v=new int[n],k=new int[4];
        byte[] kb="new String(new byte[]{72,101,120,88,86,80,78,80,97,115,115})".getBytes(StandardCharsets.UTF_8);
        for(int i=0;i<16;i++)k[i>>>2]|=(kb[i]&255)<<((i&3)*8);
        for(int i=0;i<data.length;i++)v[i>>>2]|=(data[i]&255)<<((i&3)*8);
        int rounds=6+52/n;
        if(encrypt){
            v[n-1]=data.length;int sum=0,z=v[n-1];
            for(int r=0;r<rounds;r++){
                sum+=DELTA;int e=(sum>>>2)&3,p;
                for(p=0;p<n-1;p++){int y=v[p+1];v[p]+=mx(sum,y,z,p,e,k);z=v[p];}
                v[n-1]+=mx(sum,v[0],z,n-1,e,k);z=v[n-1];
            }
        }else{
            int sum=rounds*DELTA,y=v[0];
            for(int r=0;r<rounds;r++){
                int e=(sum>>>2)&3,p;
                for(p=n-1;p>0;p--){v[p]-=mx(sum,y,v[p-1],p,e,k);y=v[p];}
                v[0]-=mx(sum,y,v[n-1],0,e,k);y=v[0];sum-=DELTA;
            }
        }
        int size=encrypt?n*4:v[n-1];
        if(!encrypt && (size<data.length-7 || size>data.length-4))throw new IllegalArgumentException();
        byte[] result=new byte[size];for(int i=0;i<size;i++)result[i]=(byte)(v[i>>>2]>>>((i&3)*8));
        return result;
    }
    static byte[] apply(String op,byte[] input)throws Exception {
        if(op.equals("Ddec")){
            StringBuilder out=new StringBuilder();
            for(String number:new String(input,StandardCharsets.UTF_8).split(","))out.append((char)Integer.parseInt(number));
            return out.toString().getBytes(StandardCharsets.UTF_8);
        }
        if(op.equals("XXenc"))return Base64.getEncoder().encode(tea(input,true));
        if(op.equals("XXdec"))return tea(Base64.getMimeDecoder().decode(input),false);
        boolean encrypt=op.endsWith("enc"),cfb=op.startsWith("F");
        byte[] key,iv;
        if(op.startsWith("P")){key=profileKey();iv=new byte[16];}
        else {iv=IV;key=hash(cfb?"(Ljava/lang/String;Ljava/lang/String)https://;t.me/noobdev24":
            "AESCBCcrptor;Java/com/jztunnel_vpn_libandroid.so_:crypto_NativeCrypto/Fdecrypt/(Ljava/lang/String;Ljava/lang/Strin");}
        byte[] result=aes(encrypt?input:Base64.getMimeDecoder().decode(input),key,iv,cfb,encrypt);
        return encrypt?Base64.getEncoder().encode(result):result;
    }
    public static void main(String[] args)throws Exception {
        var reader=new BufferedReader(new InputStreamReader(System.in,StandardCharsets.UTF_8));
        String line;
        while((line=reader.readLine())!=null){
            String[] parts=line.split("\t",2);
            if(parts.length!=2 || !Set.of("Jenc","Jdec","Fenc","Fdec","Penc","Pdec","XXenc","XXdec","Ddec").contains(parts[0]))throw new IllegalArgumentException();
            System.out.println(Base64.getEncoder().encodeToString(apply(parts[0],Base64.getDecoder().decode(parts[1]))));
        }
    }
}

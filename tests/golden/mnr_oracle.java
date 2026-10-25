// Independent JDK reference for F5.a/b/g in MNR TUNNEL PLUS build 31.
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

class mnr_oracle {
    static String outer = "¹²³⁴⁵⁶⁷⁸⁹⁰·,‽:'′";
    static String field = "\u2000\u2001\u2002\u2003\u2004\u2005\u2006\u2007\u2008\u2009\u200a\u200b\u200c\u200d\u200e\u200f";
    static byte[] utf(String text) { return text.getBytes(StandardCharsets.UTF_8); }
    static byte[] key(String secret) throws Exception {
        StringBuilder hex = new StringBuilder();
        for(byte b : utf(secret)) hex.append(String.format("%02X", b & 255));
        return MessageDigest.getInstance("SHA-256").digest(utf(hex.toString()));
    }
    static byte[] transform(String mode, byte[] input) throws Exception {
        boolean seal = mode.startsWith("seal-");
        if(seal) mode=mode.substring(5);
        String secret;
        if(mode.equals("catalog"))secret="devpro";
        else if(mode.equals("profile"))secret="demondevs";
        else if(mode.equals("field"))secret="❤️🧑‍💻Bøbõ⁰⁰!!";
        else throw new IllegalArgumentException();
        String alphabet=mode.equals("field")?field:outer;
        Cipher cipher=Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(seal?Cipher.ENCRYPT_MODE:Cipher.DECRYPT_MODE,
            new SecretKeySpec(key(secret),"AES"),new IvParameterSpec(new byte[16]));
        if(seal){
            byte[] b64=Base64.getEncoder().encode(cipher.doFinal(input));
            StringBuilder output=new StringBuilder();
            for(byte b:b64)output.append(alphabet.charAt((b & 255)>>>4)).append(alphabet.charAt(b & 15));
            return utf(output.toString());
        }
        String text=new String(input,StandardCharsets.UTF_8);
        if(text.length()%2!=0)throw new IllegalArgumentException();
        byte[] b64=new byte[text.length()/2];
        for(int i=0;i<b64.length;i++){
            int a=alphabet.indexOf(text.charAt(i*2)),b=alphabet.indexOf(text.charAt(i*2+1));
            if(a<0||b<0)throw new IllegalArgumentException();
            b64[i]=(byte)(a*16+b);
        }
        return cipher.doFinal(Base64.getDecoder().decode(b64));
    }
    public static void main(String[] args) throws Exception {
        BufferedReader in=new BufferedReader(new InputStreamReader(System.in,StandardCharsets.UTF_8));
        String line;
        while((line=in.readLine())!=null){
            String[] parts=line.split("\t",-1);
            System.out.println(Base64.getEncoder().encodeToString(transform(parts[0],Base64.getDecoder().decode(parts[1]))));
        }
    }
}

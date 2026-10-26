import java.nio.file.*;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.*;
import java.io.*;
import javax.crypto.*;
import javax.crypto.spec.*;

// Independent JDK transcription of the DEX's WakkoDev, nibble and field paths.
// Never execute APK code. Output is intended for a private verifier pipe only.
class speicers_oracle {
    static byte[] b64(String value) {
        return Base64.getDecoder().decode(value.replaceAll("\\s", "").replace('-', '+').replace('_', '/'));
    }
    static byte[] aes(byte[] key, byte[] iv, byte[] body) throws Exception {
        Cipher cipher=Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE,new SecretKeySpec(key,"AES"),new IvParameterSpec(iv));
        return cipher.doFinal(body);
    }
    static byte[] outer(String text) throws Exception {
        String alphabet="▙▚▛▜▝▞▟▃▄▅▆▇█▉▊▐";
        if (alphabet.indexOf(text.charAt(0)) >= 0) {
            byte[] packed=new byte[text.length()/2];
            for(int i=0;i<packed.length;i++)
                packed[i]=(byte)((alphabet.indexOf(text.charAt(2*i))<<4)|alphabet.indexOf(text.charAt(2*i+1)));
            StringBuilder hex=new StringBuilder();
            for(byte b:"公鸡快乐$3210VcF".getBytes(StandardCharsets.UTF_8))hex.append(String.format("%02X",b&255));
            byte[] key=MessageDigest.getInstance("SHA-256").digest(hex.toString().getBytes(StandardCharsets.US_ASCII));
            return aes(key,new byte[16],b64(new String(packed,StandardCharsets.US_ASCII)));
        }
        byte[] packed=b64(text);
        if(!new String(packed,0,8,StandardCharsets.US_ASCII).equals("WakkoDev"))throw new Exception("header");
        MessageDigest md=MessageDigest.getInstance("MD5");
        byte[] previous=new byte[0],material=new byte[48];
        for(int i=0;i<3;i++) {
            md.update(previous);md.update("ProteccionSanta$666".getBytes(StandardCharsets.UTF_8));
            previous=md.digest(Arrays.copyOfRange(packed,8,16));
            System.arraycopy(previous,0,material,16*i,16);
        }
        return aes(Arrays.copyOfRange(material,0,32),Arrays.copyOfRange(material,32,48),Arrays.copyOfRange(packed,16,packed.length));
    }
    static String field(String text) throws Exception {
        if(text.isEmpty())return text;
        byte[] raw=b64(text), key=Arrays.copyOf("Diablo2310BAX9t".getBytes(StandardCharsets.UTF_8),32);
        String rotated=new String(aes(key,Arrays.copyOfRange(raw,0,16),Arrays.copyOfRange(raw,16,raw.length)),StandardCharsets.UTF_8);
        StringBuilder out=new StringBuilder();
        for(int i=0;i<rotated.length();i++) {
            char c=rotated.charAt(i);
            if(Character.isLetter(c))c=Character.isUpperCase(c)?(char)(((c-'*')%26)+65):(char)(((c-'J')%26)+97);
            out.append(c);
        }
        return out.toString();
    }
    public static void main(String[] args) throws Exception {
        if(args[0].equals("outer")) {
            String text=Files.readString(Path.of(args[1]),StandardCharsets.UTF_8).strip();
            System.out.write(outer(text));
        } else if(args[0].equals("fields")) {
            BufferedReader input=new BufferedReader(new InputStreamReader(System.in,StandardCharsets.UTF_8));
            String line;
            while((line=input.readLine())!=null)System.out.println(Base64.getEncoder().encodeToString(field(line).getBytes(StandardCharsets.UTF_8)));
        } else throw new IllegalArgumentException("mode");
    }
}

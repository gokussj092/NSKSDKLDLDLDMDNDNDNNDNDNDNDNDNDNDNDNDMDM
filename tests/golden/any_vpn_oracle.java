import java.nio.file.*;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.*;
import java.io.*;
import javax.crypto.*;
import javax.crypto.spec.*;

// Independent JDK transcription of UtilsKey.Parser and AESHelper.
class any_vpn_oracle {
    static String open(String value) throws Exception {
        byte[] raw=Base64.getDecoder().decode(value.replaceAll("\\s", ""));
        byte[] key=MessageDigest.getInstance("SHA-256").digest("red1987".getBytes(StandardCharsets.UTF_8));
        Cipher cipher=Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE,new SecretKeySpec(key,"AES"),new IvParameterSpec(new byte[16]));
        return new String(cipher.doFinal(raw),StandardCharsets.UTF_8);
    }
    public static void main(String[] args) throws Exception {
        if(args[0].equals("outer")) {
            String text=Files.readString(Path.of(args[1]),StandardCharsets.UTF_8).strip();
            System.out.print(text.startsWith("{")?text:open(text));
        } else if(args[0].equals("fields")) {
            BufferedReader input=new BufferedReader(new InputStreamReader(System.in,StandardCharsets.UTF_8));
            String line;
            while((line=input.readLine())!=null)
                System.out.println(Base64.getEncoder().encodeToString((line.isEmpty()?line:open(line)).getBytes(StandardCharsets.UTF_8)));
        } else throw new IllegalArgumentException("mode");
    }
}

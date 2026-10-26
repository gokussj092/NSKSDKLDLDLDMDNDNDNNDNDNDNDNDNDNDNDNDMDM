// Independent transcription of StringCrypter / NoobPass / NoobCrypt in DEX3.
// All seal modes are deterministic synthetic-vector generators, not APK exports.
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

class TunnelDoomOracle {
    static byte[] utf8(String s) { return s.getBytes(StandardCharsets.UTF_8); }
    static String text(byte[] b) { return new String(b, StandardCharsets.UTF_8); }
    static byte[] sha(byte[] b) throws Exception { return MessageDigest.getInstance("SHA-256").digest(b); }
    static String noobPass() {
        String star = "up1!\u0005 ,/\u000fq&)k6ts{1305*+$";
        char[] cycle = {'Q', 'X', 'W', 'R'};
        StringBuilder s = new StringBuilder();
        for (int i=0; i<star.length(); i++) s.append((char)(star.charAt(i)^cycle[i%4]));
        return s.reverse().toString();
    }
    static byte[] xor(byte[] b) throws Exception {
        byte[] key = sha(utf8("test_key")), out = new byte[b.length];
        for (int i=0; i<b.length; i++) out[i] = (byte)(b[i]^key[i%key.length]);
        return out;
    }
    static byte[] field(byte[] b, int mode) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(mode,new SecretKeySpec(sha(utf8(noobPass())),"AES"),new IvParameterSpec(new byte[16]));
        return cipher.doFinal(b);
    }
    public static void main(String[] args) throws Exception {
        BufferedReader reader = new BufferedReader(new InputStreamReader(System.in, StandardCharsets.UTF_8));
        String line;
        while ((line=reader.readLine())!=null) {
            String[] p=line.split("\t",-1);
            byte[] data=Base64.getDecoder().decode(p[1]), out;
            switch (p[0]) {
                case "seal": out=Base64.getEncoder().encode(xor(utf8("0123456789abcdef0123456789abcdef"+text(data)))); break;
                case "open": out=utf8(text(xor(Base64.getMimeDecoder().decode(data))).substring(32)); break;
                case "field-seal": out=Base64.getEncoder().encode(field(data,Cipher.ENCRYPT_MODE)); break;
                case "field-open": out=field(Base64.getMimeDecoder().decode(data),Cipher.DECRYPT_MODE); break;
                default: throw new IllegalArgumentException("mode");
            }
            System.out.println(Base64.getEncoder().encodeToString(out));
        }
    }
}

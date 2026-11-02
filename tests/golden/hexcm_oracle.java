/* Independent JDK 17 JCA reference for HexVPN 1.7.3-Rev file envelopes.
 * Synthetic fixtures only. No Android, APK initialization or provider calls.
 * java tests/golden/hexcm_oracle.java encrypt single|double input.json output.hexcm
 * java tests/golden/hexcm_oracle.java decrypt input.hexcm output.json
 */
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;
import java.security.MessageDigest;
import javax.crypto.*;
import javax.crypto.spec.*;

class HexcmOracle {
    static final char[] PASSWORD = "JotchuaZDevz105V".toCharArray();
    static final byte[] INNER = HexFormat.of().parseHex(
        "1e7e5f507b01878ca32f4a1a74804e22cb1a4fd91bc4ff93f315474a9c55e8ad");
    static byte[] sequence(int n, int start) {
        byte[] out = new byte[n];
        for (int i=0; i<n; i++) out[i]=(byte)(start+i);
        return out;
    }
    static byte[] aes(int mode, byte[] data, byte[] salt, byte[] nonce) throws Exception {
        PBEKeySpec spec = new PBEKeySpec(PASSWORD, salt, 100000, 256);
        byte[] key = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256").generateSecret(spec).getEncoded();
        spec.clearPassword();
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(mode, new SecretKeySpec(key,"AES"), new GCMParameterSpec(128,nonce));
        return cipher.doFinal(data);
    }
    static byte[] chacha(int mode, byte[] data, byte[] nonce) throws Exception {
        Cipher cipher = Cipher.getInstance("ChaCha20-Poly1305");
        cipher.init(mode, new SecretKeySpec(INNER,"ChaCha20"),new IvParameterSpec(nonce));
        return cipher.doFinal(data);
    }
    static byte[] join(byte[]... items) {
        int n=0; for(byte[] item:items)n+=item.length;
        byte[] out=new byte[n];n=0;
        for(byte[] item:items){System.arraycopy(item,0,out,n,item.length);n+=item.length;}
        return out;
    }
    public static void main(String[] args) throws Exception {
        if(args[0].equals("sign")) {
            String unsigned=Files.readString(Path.of(args[1]),StandardCharsets.UTF_8);
            String digest=HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(
                (unsigned+new String(PASSWORD)).getBytes(StandardCharsets.UTF_8)));
            Files.writeString(Path.of(args[2]),unsigned.substring(0,unsigned.length()-1)+",\"signature\":\""+digest+"\"}",StandardCharsets.UTF_8);
        } else if(args[0].equals("encrypt")) {
            byte[] plain=Files.readAllBytes(Path.of(args[2]));
            if(args[1].startsWith("double")){
                byte[] nonce=sequence(12,64);
                byte[] encrypted=chacha(Cipher.ENCRYPT_MODE,plain,nonce);
                if(args[1].equals("double-bad-tag")) encrypted[encrypted.length-1]^=1;
                plain=Base64.getEncoder().encode(join(nonce,encrypted));
            }
            byte[] salt=sequence(16,0),nonce=sequence(12,32);
            Files.write(Path.of(args[3]),Base64.getEncoder().encode(join(salt,nonce,aes(Cipher.ENCRYPT_MODE,plain,salt,nonce))));
        } else if(args[0].equals("decrypt")) {
            String wire=Files.readString(Path.of(args[1]),StandardCharsets.US_ASCII).replaceAll("[ \\t\\r\\n]", "");
            byte[] raw=Base64.getDecoder().decode(wire);
            byte[] plain=aes(Cipher.DECRYPT_MODE,Arrays.copyOfRange(raw,28,raw.length),Arrays.copyOf(raw,16),Arrays.copyOfRange(raw,16,28));
            if(plain[0]!='{') {
                byte[] inner=Base64.getDecoder().decode(plain);
                plain=chacha(Cipher.DECRYPT_MODE,Arrays.copyOfRange(inner,12,inner.length),Arrays.copyOf(inner,12));
            }
            Files.write(Path.of(args[2]),plain);
        } else throw new IllegalArgumentException("Unknown mode");
    }
}

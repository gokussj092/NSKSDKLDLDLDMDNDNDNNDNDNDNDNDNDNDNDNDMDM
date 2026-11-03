// Independent JCA oracle for synthetic fixtures; no vendor code or real secrets.
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public final class EnvelopeOracle {
    public static void main(String[] args) throws Exception {
        if (args.length != 3) throw new IllegalArgumentException("encode|decode input output");
        String password = System.getenv("HALCON_SYNTHETIC_PASSWORD");
        if (password == null || password.isEmpty()) throw new IllegalArgumentException("Missing test password");
        byte[] key = MessageDigest.getInstance("SHA-256").digest(password.getBytes(StandardCharsets.UTF_8));
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        String alphabet = "▙▚▛▜▝▞▟▃▄▅▆▇█▉▊▐";
        if (args[0].equals("encode")) {
            byte[] iv = new byte[12];
            for (int i = 0; i < 12; i++) iv[i] = (byte)i;
            cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), new GCMParameterSpec(128, iv));
            byte[] encrypted = cipher.doFinal(Files.readAllBytes(Path.of(args[1])));
            byte[] envelope = new byte[12 + encrypted.length];
            System.arraycopy(iv, 0, envelope, 0, 12);
            System.arraycopy(encrypted, 0, envelope, 12, encrypted.length);
            StringBuilder out = new StringBuilder();
            for (byte b : Base64.getEncoder().encode(envelope)) {
                out.append(alphabet.charAt((b & 255) >>> 4));
                out.append(alphabet.charAt(b & 15));
            }
            Files.writeString(Path.of(args[2]), out.toString(), StandardCharsets.UTF_8);
        } else if (args[0].equals("decode")) {
            String text = Files.readString(Path.of(args[1]), StandardCharsets.UTF_8).trim();
            if ((text.length() & 1) != 0) throw new IllegalArgumentException("Odd symbol count");
            byte[] b64 = new byte[text.length()/2];
            for (int i = 0; i < b64.length; i++) {
                int hi = alphabet.indexOf(text.charAt(i*2));
                int lo = alphabet.indexOf(text.charAt(i*2+1));
                if (hi < 0 || lo < 0) throw new IllegalArgumentException("Invalid symbol");
                b64[i] = (byte)((hi << 4) | lo);
            }
            byte[] envelope = Base64.getDecoder().decode(b64);
            if (envelope.length < 28) throw new IllegalArgumentException("Truncated envelope");
            cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"),
                        new GCMParameterSpec(128, Arrays.copyOf(envelope, 12)));
            Files.write(Path.of(args[2]), cipher.doFinal(Arrays.copyOfRange(envelope, 12, envelope.length)));
        } else throw new IllegalArgumentException("Unknown operation");
    }
}

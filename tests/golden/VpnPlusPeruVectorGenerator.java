// Independent OpenJDK/JCE producer. Synthetic data only; no Android dependency.
// Run: java tests/golden/VpnPlusPeruVectorGenerator.java > tests/golden/vpn_plus_peru_vectors.json
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.HexFormat;
import java.security.MessageDigest;
import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

class VpnPlusPeruVectorGenerator {
    static byte[] join(byte[]... chunks) throws Exception {
        var out = new java.io.ByteArrayOutputStream();
        for (byte[] b : chunks) out.write(b);
        return out.toByteArray();
    }
    static byte[] hex(String s) { return HexFormat.of().parseHex(s); }
    static String encrypt(int v, String text) throws Exception {
        byte[] salt = hex("000102030405060708090a0b0c0d0e0f");
        byte[] iv = hex("f0e0d0c0b0a090807060504030201000");
        String password = "AkuntVPN@2024#SecretKey$v1";
        if (v >= 2) {
            // APK construirClave / construirClaveBase output. V3 deliberately
            // retains the signed-byte rotation behavior of the Android code.
            byte[] base = hex(v == 2
                ? "416b756e7456706e5f5375703372234b33795f323032362476325f53683464307721416b6e74"
                : "a1ab75ae745670ae5f5375703372234b33795f323032362476325f53e834e4307721416b6e745839247051");
            if (v == 3) base = join(base, MessageDigest.getInstance("SHA-256").digest(
                join(base, "AkuntVPN_v3_fixed_salt_2026_secure_key".getBytes(StandardCharsets.UTF_8))));
            password = new String(base, StandardCharsets.ISO_8859_1);
        } else salt = "AkuntVPN_Salt_2024_Fixed_0001".getBytes(StandardCharsets.UTF_8);
        byte[] key = SecretKeyFactory.getInstance(v == 1 ? "PBKDF2WithHmacSHA1" : "PBKDF2WithHmacSHA256")
            .generateSecret(new PBEKeySpec(password.toCharArray(), salt, v == 1 ? 1000 : v == 2 ? 12000 : 15000, 256)).getEncoded();
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), new IvParameterSpec(iv));
        byte[] ct = cipher.doFinal(text.getBytes(StandardCharsets.UTF_8));
        byte[] body = v == 1 ? join(iv, ct) : join(salt, iv, ct);
        if (v >= 2) {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(key, "HmacSHA256"));
            body = join(body, mac.doFinal(body));
        }
        return (v == 1 ? "" : "AKN" + v + ":") + Base64.getEncoder().encodeToString(body);
    }
    public static void main(String[] args) throws Exception {
        String text = "{\"host\":\"vpn.example.invalid\",\"port\":443,\"pass\":\"synthetic-only\","
            + "\"payload\":\"GET / HTTP/1.1\\r\\nHost: example.invalid\\r\\n\\r\\n\","
            + "\"__bloqueo_id\":true,\"__id_permitido\":\"synthetic-device\",\"__mensaje\":\"Perú 日本語\","
            + "\"future\":{\"list\":[null,false,0,{\"keep\":true}]}}";
        System.out.print("{\n  \"producer\": \"OpenJDK/JCE, deterministic salt and IV, synthetic JSON\",\n  \"expected\": " + text + ",\n  \"vectors\": [\n");
        for (int v = 1; v <= 3; v++)
            System.out.print("    {\"version\": " + v + ", \"data\": \"" + encrypt(v, text) + "\"}" + (v < 3 ? "," : "") + "\n");
        System.out.println("  ]\n}");
    }
}

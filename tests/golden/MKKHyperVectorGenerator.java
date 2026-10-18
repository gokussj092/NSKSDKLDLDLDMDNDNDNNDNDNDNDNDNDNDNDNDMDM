// Synthetic reference: standard JCE, independent of the Python implementations.
// Run: java tests/golden/MKKHyperVectorGenerator.java
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

class MKKHyperVectorGenerator {
    static String quote(String s) {
        StringBuilder b = new StringBuilder("\"");
        for (char c : s.toCharArray()) {
            switch (c) {
                case '"': b.append("\\\""); break;
                case '\\': b.append("\\\\"); break;
                case '\r': b.append("\\r"); break;
                case '\n': b.append("\\n"); break;
                case '\t': b.append("\\t"); break;
                default: if (c < 32) b.append(String.format("\\u%04x", (int)c)); else b.append(c);
            }
        }
        return b.append('"').toString();
    }
    static byte[] catalogKey() throws Exception {
        byte[] encoded = Base64.getDecoder().decode("LSFOWUI9YDomFDQkQTxRawMLfCM=");
        byte[] key = "invisiVpnSecure2024".getBytes(StandardCharsets.UTF_8);
        for (int i = 0; i < encoded.length; i++) encoded[i] ^= key[i % key.length];
        return MessageDigest.getInstance("SHA-256").digest(encoded);
    }
    static String b64(byte[] data) { return Base64.getEncoder().encodeToString(data); }
    static String catalog(String clear, boolean appended) throws Exception {
        byte[] nonce = {0,1,2,3,4,5,6,7,8,9,10,11};
        Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
        c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(catalogKey(), "AES"), new GCMParameterSpec(128, nonce));
        byte[] encrypted = c.doFinal(clear.getBytes(StandardCharsets.UTF_8));
        String result = "{\"nonce\":" + quote(b64(nonce)) + ",\"cipher_text\":";
        if (appended) return result + quote(b64(encrypted)) + "}";
        return result + quote(b64(Arrays.copyOf(encrypted, encrypted.length-16))) + ",\"mac\":"
            + quote(b64(Arrays.copyOfRange(encrypted, encrypted.length-16, encrypted.length))) + "}";
    }
    static String profile(String clear) throws Exception {
        byte[] iv = {15,14,13,12,11,10,9,8,7,6,5,4,3,2,1,0};
        byte[] key = Arrays.copyOf("MKKHyperVPN_2025_SecureKey_v1.0!".getBytes(StandardCharsets.UTF_8), 32);
        Cipher c = Cipher.getInstance("AES/CBC/PKCS5Padding");
        c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), new IvParameterSpec(iv));
        byte[] encrypted = c.doFinal(clear.getBytes(StandardCharsets.UTF_8));
        return "mkk://" + b64(ByteBuffer.allocate(16+encrypted.length).put(iv).put(encrypted).array());
    }
    public static void main(String[] args) throws Exception {
        if (args.length == 5 && args[0].equals("--decode-catalog")) {
            Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
            c.init(Cipher.DECRYPT_MODE, new SecretKeySpec(catalogKey(), "AES"),
                new GCMParameterSpec(128, Base64.getDecoder().decode(args[1])));
            byte[] cipher = Base64.getDecoder().decode(Files.readString(Path.of(args[2])).trim());
            byte[] tag = Base64.getDecoder().decode(args[3]);
            Files.write(Path.of(args[4]), c.doFinal(ByteBuffer.allocate(cipher.length+tag.length).put(cipher).put(tag).array()));
            return;
        }
        String vmess = "{\"v\":\"2\",\"ps\":\"Perú 日本 𝄞\",\"add\":\"example.invalid\",\"port\":\"443\",\"id\":\"00000000-0000-0000-0000-000000000000\",\"net\":\"ws\",\"path\":\"/test\",\"tls\":\"tls\",\"payload\":\"First\\r\\nSecond\\n\",\"future\":{\"value\":null}}";
        String[] uris = {
            "vless://00000000-0000-0000-0000-000000000000@[2001:db8::1]:443?type=ws&path=%2Ftest&x=1&x=2&empty=#Per%C3%BA",
            "vmess://" + b64(vmess.getBytes(StandardCharsets.UTF_8)),
            "trojan://fixture-only@example.invalid:443?security=tls#Synthetic",
            "ss://" + b64("aes-256-gcm:fixture-only".getBytes(StandardCharsets.UTF_8)) + "@example.invalid:443#Synthetic",
            "socks://synthetic:fixture-only@example.invalid:1080#Synthetic"
        };
        String server = "{\"flag\":\"SG\",\"name\":\"Synthetic 日本 𝄞\",\"key\":" + quote(uris[0]) + ",\"vip\":true,\"future\":{\"keep\":[null,false,\"\"]}}";
        String doc = "{\"version\":\"synthetic-97\",\"servers\":[" + server + "],\"future\":{\"keep\":true}}";
        StringBuilder profiles = new StringBuilder(), invalid = new StringBuilder();
        for (int i = 0; i < uris.length; i++) {
            if (i > 0) profiles.append(',');
            profiles.append("{\"data\":").append(quote(profile(uris[i]))).append(",\"uri\":").append(quote(uris[i])).append('}');
        }
        String[] bad = {"{\"servers\":[],\"a\":1,\"a\":2}", "{\"servers\":[],\"a\":NaN}",
            "{\"servers\":[],\"a\":1e999}", "{\"servers\":[],\"a\":\"\\ud800\"}", "{broken}", "{\"servers\":[1]}", "{}"};
        for (int i = 0; i < bad.length; i++) { if (i > 0) invalid.append(','); invalid.append(quote(catalog(bad[i], false))); }
        System.out.println("{\"source\":\"Synthetic OpenJDK/JCE AES-GCM and AES-CBC; no real server data\",\"catalog\":" + quote(catalog(doc, false))
            + ",\"appendedCatalog\":" + quote(catalog(doc, true)) + ",\"expectedCatalog\":" + doc
            + ",\"profiles\":[" + profiles + "],\"expectedVmess\":" + vmess + ",\"invalidCatalogs\":[" + invalid + "]}");
    }
}

// Synthetic vectors only. Run: java tests/golden/DTunnelModVectorGenerator.java
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

class DTunnelModVectorGenerator {
    static final String SEED = "DTunnelModSecret-API-9c69a0b72b442ccac3e6aaaa7630d12f2b351fe395e9fe667efa0907cde90da5";
    static String quote(String s) {
        StringBuilder b = new StringBuilder("\"");
        for (char c : s.toCharArray()) {
            switch (c) {
                case '"': b.append("\\\""); break;
                case '\\': b.append("\\\\"); break;
                case '\n': b.append("\\n"); break;
                case '\r': b.append("\\r"); break;
                case '\t': b.append("\\t"); break;
                default:
                    if (c < 32) b.append(String.format("\\u%04x", (int)c));
                    else b.append(c);
            }
        }
        return b.append('"').toString();
    }
    static String encrypt(String plain) throws Exception {
        byte[] key = MessageDigest.getInstance("SHA-256").digest(SEED.getBytes(StandardCharsets.UTF_8));
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), new IvParameterSpec(new byte[16]));
        return Base64.getEncoder().encodeToString(cipher.doFinal(plain.getBytes(StandardCharsets.UTF_8)));
    }
    static String vector(String name, String kind, String expected, String plain) throws Exception {
        return "{\"name\":"+quote(name)+",\"kind\":"+quote(kind)+",\"expected\":"+quote(expected)+",\"data\":"+quote(encrypt(plain))+"}";
    }
    public static void main(String[] args) throws Exception {
        String payload = "GET / HTTP/1.1\r\nHost: example.invalid\r\n\r\n";
        String v2ray = "{\"outbounds\":[{\"protocol\":\"vless\",\"settings\":{\"vnext\":[{\"address\":\"example.invalid\",\"port\":443}]}}]}";
        String p1 = "{\"id\":7,\"category_id\":42,\"user_id\":\"synthetic-owner\",\"sorter\":9,\"name\":\"Prueba Perú 日本\",\"mode\":\"SSH_DIRECT\",\"server\":\"example.invalid\",\"port\":22,\"username\":\"synthetic\",\"password\":\"fixture-only\",\"payload\":"+quote(payload)+",\"future\":{\"enabled\":false,\"empty\":\"\",\"nothing\":null,\"items\":[1,2]}}";
        String p2 = "{\"id\":8,\"mode\":\"V2RAY\",\"config\":"+quote(v2ray)+",\"unknown\":true}";
        String profiles = "["+p1+","+p2+"]";
        String layoutItem = "{\"name\":\"title\",\"value\":\"Synthetic layout\",\"future\":123}";
        String layout = "["+layoutItem+"]";
        String texts = "[{\"label\":\"connect\",\"text\":\"Conectar\",\"unknown\":null}]";
        String link = "vpn://"+Base64.getEncoder().encodeToString(p1.getBytes(StandardCharsets.UTF_8));
        System.out.println("{\"source\":\"OpenJDK/JCE AES-CBC synthetic vectors; no service credentials\",\"expectedProfiles\":"+profiles+",\"expectedLayout\":"+layout+",\"expectedTexts\":"+texts+",\"expectedEmpty\":[],\"link\":"+quote(link)+",\"vectors\":["
            +vector("catalog", "catalog", "expectedProfiles", "["+quote(p1)+","+quote(p2)+"]")+","
            +vector("catalog-objects", "catalog", "expectedProfiles", profiles)+","
            +vector("layout", "layout", "expectedLayout", "["+quote(layoutItem)+"]")+","
            +vector("texts", "texts", "expectedTexts", texts)+","
            +vector("empty", "catalog", "expectedEmpty", "[]")+"]}");
    }
}

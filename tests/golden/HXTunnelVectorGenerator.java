// Synthetic vectors, independent of Python: APK XXTEA and native hex/XOR format.
// DataOutputStream.writeUTF reproduces JNI modified UTF-8, including surrogate pairs.
// Run: java tests/golden/HXTunnelVectorGenerator.java
import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.Base64;

class HXTunnelVectorGenerator {
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
    static int mx(int sum, int y, int z, int p, int e, int[] key) {
        return ((sum ^ y) + (key[(p & 3) ^ e] ^ z)) ^ (((z >>> 5) ^ (y << 2)) + ((y >>> 3) ^ (z << 4)));
    }
    static int[] key() {
        byte[] bytes = Arrays.copyOf("Princie!".getBytes(StandardCharsets.UTF_8), 16);
        int[] key = new int[4];
        ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN).asIntBuffer().get(key);
        return key;
    }
    static String catalog(String text) {
        byte[] plain = text.getBytes(StandardCharsets.UTF_8);
        int[] v = new int[(plain.length + 3) / 4 + 1], key = key();
        for (int i = 0; i < plain.length; i++) v[i >>> 2] |= (plain[i] & 255) << ((i & 3) << 3);
        v[v.length - 1] = plain.length;
        int last = v.length - 1, z = v[last], sum = 0;
        for (int rounds = 6 + 52 / v.length; rounds > 0; rounds--) {
            sum += -1638454863; int e = (sum >>> 2) & 3;
            for (int p = 0; p < last; p++) { v[p] += mx(sum, v[p+1], z, p, e, key); z = v[p]; }
            v[last] += mx(sum, v[0], z, last, e, key); z = v[last];
        }
        ByteBuffer out = ByteBuffer.allocate(v.length * 4).order(ByteOrder.LITTLE_ENDIAN);
        for (int word : v) out.putInt(word);
        return Base64.getEncoder().encodeToString(out.array());
    }
    static byte[] decryptCatalog(String text) {
        byte[] data = Base64.getMimeDecoder().decode(text);
        if (data.length < 8 || data.length % 4 != 0) throw new IllegalArgumentException("word count");
        int[] v = new int[data.length / 4], key = key();
        ByteBuffer.wrap(data).order(ByteOrder.LITTLE_ENDIAN).asIntBuffer().get(v);
        int last = v.length - 1, y = v[0];
        for (int sum = (6 + 52 / v.length) * -1638454863; sum != 0; sum -= -1638454863) {
            int e = (sum >>> 2) & 3;
            for (int p = last; p > 0; p--) { v[p] -= mx(sum, y, v[p-1], p, e, key); y = v[p]; }
            v[0] -= mx(sum, y, v[last], 0, e, key); y = v[0];
        }
        int length = v[last];
        if (length < data.length - 7 || length > data.length - 4) throw new IllegalArgumentException("length");
        ByteBuffer out = ByteBuffer.allocate(data.length).order(ByteOrder.LITTLE_ENDIAN);
        for (int word : v) out.putInt(word);
        return Arrays.copyOf(out.array(), length);
    }
    static String profile(String text) throws Exception {
        ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        new DataOutputStream(buffer).writeUTF(text);
        byte[] mutf8 = buffer.toByteArray(), key = "4%PdXch>fkP]".getBytes(StandardCharsets.US_ASCII);
        StringBuilder hex = new StringBuilder();
        for (int i = 2; i < mutf8.length; i++) hex.append(String.format("%02x", (mutf8[i] ^ key[(i-2) % key.length]) & 255));
        return hex.toString();
    }
    public static void main(String[] args) throws Exception {
        if (args.length == 3 && args[0].equals("--decode-catalog")) {
            Files.write(Path.of(args[2]), decryptCatalog(Files.readString(Path.of(args[1])))); return;
        }
        String server = "{\"name\":\"Synthetic server\",\"host\":\"example.invalid\",\"port\":\"22\",\"future\":null}";
        String payload = "GET / HTTP/1.1\r\nHost: example.invalid\r\n\r\n";
        String profile = "{\"friendly_name\":\"Prueba 日本 Perú 𝄞\",\"payload\":" + quote(payload)
            + ",\"tweak_password\":\"fixture-only\",\"hwid_lock\":\"SYNTHETIC-DEVICE\",\"tweak_expiry\":\"2000-01-01-00-00\",\"block_rooted\":\"true\",\"mobile_data_only\":\"true\",\"method\":\"ssh\",\"host\":\"example.invalid\",\"port\":\"22\",\"message\":\"First\\nSecond\\r\\nThird\",\"embedded\":" + quote(server) + ",\"future\":{\"values\":[null,false,\"\"]}}";
        String catalog = "{\"Version\":\"synthetic-1\",\"Username\":\"synthetic\",\"Password\":\"fixture-only\",\"Free_servers\":[" + server
            + "],\"Premium_servers\":[" + server + "],\"Vip_servers\":[" + server + "],\"Private_servers\":[" + server
            + "],\"Payloads\":[" + profile + "],\"Changelogs\":\"First\\r\\nSecond\",\"future\":{\"keep\":true}}";
        StringBuilder lengths = new StringBuilder();
        for (int i = 0; i < 4; i++) {
            String text = "{\"Payloads\":[],\"padding\":" + quote("x".repeat(i)) + "}";
            if (i > 0) lengths.append(',');
            lengths.append("{\"data\":").append(quote(catalog(text))).append(",\"expected\":").append(text)
                .append(",\"utf8Bytes\":").append(text.getBytes(StandardCharsets.UTF_8).length).append('}');
        }
        String[] invalid = {"{\"Payloads\":[],\"a\":1,\"a\":2}", "{\"Payloads\":[],\"a\":NaN}",
            "{\"Payloads\":[],\"a\":1e999}", "{\"Payloads\":[],\"a\":\"\\ud800\"}", "[]", "{broken}"};
        StringBuilder bad = new StringBuilder();
        for (int i = 0; i < invalid.length; i++) {
            if (i > 0) bad.append(',');
            bad.append("{\"catalog\":").append(quote(catalog(invalid[i]))).append(",\"profile\":").append(quote(profile(invalid[i]))).append('}');
        }
        System.out.println("{\"source\":\"Synthetic Java APK XXTEA + DataOutputStream JNI UTF-8/hex/XOR; no real server data\",\"catalog\":" + quote(catalog(catalog))
            + ",\"expectedCatalog\":" + catalog + ",\"profile\":" + quote(profile(profile)) + ",\"expectedProfile\":" + profile
            + ",\"lengthVectors\":[" + lengths + "],\"invalidVectors\":[" + bad + "]}");
    }
}

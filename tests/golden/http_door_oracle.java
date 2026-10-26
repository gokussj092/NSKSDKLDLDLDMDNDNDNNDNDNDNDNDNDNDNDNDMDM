// Independent JDK DESKeySpec + Cipher("DES") + Properties.loadFromXML.
// Batch protocol: seal/open TAB Base64 bytes. Only synthetic data in tests.
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.*;
import javax.crypto.*;
import javax.crypto.spec.DESKeySpec;

class http_door_oracle {
    static String quote(String s) {
        StringBuilder b = new StringBuilder("\"");
        for (char c : s.toCharArray()) {
            if (c == '"' || c == '\\') b.append('\\').append(c);
            else if (c < 32 || Character.isSurrogate(c)) b.append(String.format("\\u%04x", (int)c));
            else b.append(c);
        }
        return b.append('"').toString();
    }
    static String b64(byte[] bytes) { return Base64.getEncoder().encodeToString(bytes); }
    public static void main(String[] args) throws Exception {
        BufferedReader in = new BufferedReader(new InputStreamReader(System.in, StandardCharsets.UTF_8));
        String line;
        while ((line = in.readLine()) != null) {
            String[] parts = line.split("\t", -1);
            byte[] source = Base64.getDecoder().decode(parts[1]);
            boolean seal = parts[0].equals("seal");
            if (!seal && !parts[0].equals("open")) throw new IllegalArgumentException();
            DESKeySpec spec = new DESKeySpec("cinbdf665$4".getBytes(StandardCharsets.UTF_8));
            Cipher cipher = Cipher.getInstance("DES");
            cipher.init(seal ? Cipher.ENCRYPT_MODE : Cipher.DECRYPT_MODE,
                SecretKeyFactory.getInstance("DES").generateSecret(spec));
            byte[] transformed = cipher.doFinal(source);
            byte[] xml = seal ? source : transformed;
            Properties props = new Properties();
            props.loadFromXML(new ByteArrayInputStream(xml));
            ArrayList<String> keys = new ArrayList<>(props.stringPropertyNames());
            Collections.sort(keys);
            ArrayList<String> items = new ArrayList<>();
            for (String key : keys) items.add(quote(key) + ":" + quote(props.getProperty(key)));
            String json = "{" + String.join(",", items) + "}";
            System.out.println(b64(transformed) + "\t" + b64(json.getBytes(StandardCharsets.UTF_8)));
        }
    }
}

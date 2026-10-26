import java.io.*;
import java.nio.*;
import java.nio.file.*;
import java.nio.charset.StandardCharsets;
import java.util.*;

// Independent batch oracle. Reuses the proven Dalvik XXTEA reference, not Python.
class bd_net_oracle {
    static String readUTF(byte[] raw) throws Exception {
        if (raw.length > 65535) throw new IllegalArgumentException("reference vector exceeds readUTF limit");
        var bytes = new ByteArrayOutputStream();
        var writer = new DataOutputStream(bytes);
        writer.writeShort(raw.length); writer.write(raw);
        return new DataInputStream(new ByteArrayInputStream(bytes.toByteArray())).readUTF();
    }
    static String b64(byte[] raw) { return Base64.getEncoder().encodeToString(raw); }
    public static void main(String[] args) throws Exception {
        var reader = new BufferedReader(new InputStreamReader(System.in, StandardCharsets.US_ASCII));
        String line;
        while ((line = reader.readLine()) != null) {
            var fields = line.split("\t", -1);
            byte[] input = Base64.getDecoder().decode(fields[1]);
            if (fields[0].equals("C")) {
                System.out.println("T\t" + b64(apna_oracle.catalog(input)));
                continue;
            }
            String token = new String(input, StandardCharsets.US_ASCII).strip();
            if (token.toLowerCase(Locale.ROOT).startsWith("bdnet://")) token = token.substring(8);
            byte[] raw = HexFormat.of().parseHex(token), key = "4%PdXch>fkP]".getBytes(StandardCharsets.US_ASCII);
            for (int i=0; i<raw.length; i++) raw[i] ^= key[i % key.length];
            try {
                System.out.println("T\t" + b64(readUTF(raw).getBytes(StandardCharsets.UTF_8)));
            } catch (UTFDataFormatException error) {
                int nul = -1;
                for (int i=0; i<raw.length; i++) if (raw[i]==0) { nul=i; break; }
                if (nul < 0) throw error;
                String prefix = readUTF(Arrays.copyOf(raw, nul));
                System.out.println("B\t" + b64(prefix.getBytes(StandardCharsets.UTF_8)) + "\t" + b64(raw));
            }
        }
    }
}

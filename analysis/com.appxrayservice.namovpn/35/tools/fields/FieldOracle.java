import java.io.*;
import java.nio.*;
import java.nio.charset.*;
import java.util.Base64;

/** Independent reference for f60.m: standard Base64 bytes, then UTF-8.
 * Android's permissive invalid-byte behavior is deliberately not reproduced:
 * the backend fails closed. E emits Android DEFAULT's 76-column LF wrapping.
 * Input/output lines transport private values as Base64; never log them.
 */
class FieldOracle {
    public static void main(String[] args) throws Exception {
        var in = new BufferedReader(new InputStreamReader(System.in, StandardCharsets.UTF_8));
        String line;
        while ((line = in.readLine()) != null) {
            String[] parts = line.split("\t", -1);
            byte[] input = Base64.getDecoder().decode(parts[1]);
            byte[] result;
            if (parts[0].equals("E")) {
                String encoded = Base64.getMimeEncoder(76, new byte[]{10}).encodeToString(input);
                result = (encoded.isEmpty() ? "" : encoded + "\n").getBytes(StandardCharsets.US_ASCII);
            } else if (parts[0].equals("D")) {
                String text = StandardCharsets.US_ASCII.newDecoder()
                    .onMalformedInput(CodingErrorAction.REPORT).decode(ByteBuffer.wrap(input)).toString();
                String compact = text.replaceAll("\\s+", "");
                if (!compact.matches("[A-Za-z0-9+/]*={0,2}") || compact.length()%4==1 ||
                    (compact.contains("=") && compact.length()%4!=0) ||
                    (!text.isEmpty() && compact.isEmpty())) throw new IllegalArgumentException("Base64");
                result = Base64.getDecoder().decode(compact);
                StandardCharsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT)
                    .decode(ByteBuffer.wrap(result));
            } else throw new IllegalArgumentException("mode");
            System.out.println(Base64.getEncoder().encodeToString(result));
        }
    }
}

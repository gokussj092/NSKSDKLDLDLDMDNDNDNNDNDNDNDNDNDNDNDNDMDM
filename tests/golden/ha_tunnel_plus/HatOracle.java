import java.nio.charset.StandardCharsets;
import java.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
/** Synthetic JCA oracle for the historical .hat envelope, no real accounts. */
public final class HatOracle {
    private static final String XOR = "**rVg7EkL~c2`D[aNn";
    static String field(String value) {
        StringBuilder out = new StringBuilder();
        for (int i=0;i<value.length();i++)
            out.append((char)(value.charAt(i) ^ XOR.charAt(i % XOR.length())));
        return Base64.getEncoder().encodeToString(out.toString().getBytes(StandardCharsets.UTF_8));
    }
    public static void main(String[] args) throws Exception {
        String[] values = {"SSH", "GET / HTTP/1.1\r\nHost: example.test\r\n\r\n", "café ñ 中文", "🚀example.test😀", "", "A".repeat(63)};
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(Base64.getDecoder().decode("zbNkuNCGSLivpEuep3BcNA=="),"AES"));
        for (String value : values) {
            String encoded = field(value);
            String document = "{\"profilev5\":{\"custom_payload\":\"" + encoded + "\"},\"protextras\":{\"anti_sniff\":true},\"unknown\":{\"keep\":[null,false,23]}}";
            System.out.println(Base64.getEncoder().encodeToString(value.getBytes(StandardCharsets.UTF_8)) + "\t" + encoded + "\t" + Base64.getEncoder().encodeToString(cipher.doFinal(document.getBytes(StandardCharsets.UTF_8))));
        }
    }
}

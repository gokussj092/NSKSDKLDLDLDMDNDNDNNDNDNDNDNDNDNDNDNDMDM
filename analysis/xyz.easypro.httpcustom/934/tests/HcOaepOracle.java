import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyFactory;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;

/** Independent JCE oracle with the parameters captured in original build 934. */
class HcOaepOracle {
  public static void main(String[] args) throws Exception {
    var publicKey = KeyFactory.getInstance("RSA").generatePublic(
        new X509EncodedKeySpec(Files.readAllBytes(Path.of(args[0]))));
    byte[] data = System.in.readAllBytes();
    if (data.length != 32) throw new IllegalArgumentException("Expected synthetic 32-byte content key");
    Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPPadding");
    cipher.init(Cipher.ENCRYPT_MODE, publicKey,
        new OAEPParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA1, PSource.PSpecified.DEFAULT));
    System.out.print(Base64.getEncoder().encodeToString(cipher.doFinal(data)));
  }
}

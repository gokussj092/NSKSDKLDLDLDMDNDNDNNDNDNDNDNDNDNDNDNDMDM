import java.nio.file.*;
import java.nio.*;
import java.nio.charset.*;
import java.security.MessageDigest;
import java.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.spec.*;
/** Independent standard JCA only. No Android/APK classes are loaded. */
class ProOracle {
  static String utf8(byte[] b) throws Exception {
    return StandardCharsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT).onUnmappableCharacter(CodingErrorAction.REPORT).decode(ByteBuffer.wrap(b)).toString();
  }
  public static void main(String[] args) throws Exception {
    for(String line:Files.readAllLines(Path.of(args[0]),StandardCharsets.UTF_8)) {
      String[] p=line.split("\t",-1);
      byte[] seed=Base64.getDecoder().decode(p[1]);
      byte[] data=Base64.getDecoder().decode(p[2]);
      Cipher c=Cipher.getInstance("AES/CBC/PKCS5Padding");
      c.init(p[0].equals("seal")?Cipher.ENCRYPT_MODE:Cipher.DECRYPT_MODE,new SecretKeySpec(MessageDigest.getInstance("SHA-256").digest(seed),"AES"),new IvParameterSpec(new byte[16]));
      byte[] out=c.doFinal(data);
      if(p[0].equals("open"))utf8(out); // strict, unlike Java's replacement decoder
      System.out.println(Base64.getEncoder().encodeToString(out));
    }
  }
}

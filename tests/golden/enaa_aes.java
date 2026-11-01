import java.io.*;
import java.util.*;
import javax.crypto.*;
import javax.crypto.spec.*;

/** JDK AES-GCM reference, no APK classes or production Python imports.
 * One line: E/D TAB keyHex TAB saltHex TAB nonceHex TAB base64(input).
 * Output: base64(ciphertext+tag) or base64(authenticated plaintext).
 */
class enaa_aes {
 public static void main(String[] args) throws Exception {
  var reader = new BufferedReader(new InputStreamReader(System.in));
  String line;
  while ((line=reader.readLine()) != null) {
   var fields=line.split("\t",-1);
   var hex=HexFormat.of();
   var cipher=Cipher.getInstance("AES/GCM/NoPadding");
   cipher.init(fields[0].equals("E")?Cipher.ENCRYPT_MODE:Cipher.DECRYPT_MODE,
    new SecretKeySpec(hex.parseHex(fields[1]),"AES"),new GCMParameterSpec(128,hex.parseHex(fields[3])));
   cipher.updateAAD(hex.parseHex(fields[2]));
   System.out.println(Base64.getEncoder().encodeToString(cipher.doFinal(Base64.getDecoder().decode(fields[4]))));
  }
 }
}

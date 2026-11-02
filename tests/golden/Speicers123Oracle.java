import java.nio.file.*;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;
import java.util.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import com.google.gson.*;
/** Independent JCA transcription of the recovered 123 SPCF1 primitives. */
class Speicers123Oracle {
 static final String PUBLIC_KEY="MIIBojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKCAYEA3AjjZkkCkznJzdy9YO7fPQUCaE7FrWnQeazmI7uMt6CrPL4XwXIYQDu+WSAKyQUkfCRrDnWBDYZac4cHjqxnYLyu/gaFvjIu6VAqq/GwZ3RzK586ST+AIH4nT++BnHQOzh9uciEhUM6xuZfGh2XJm+51WCytP0tijSKglw37O+WIK6+fwbvtS1UJYLsDSmfbzRFO8wX3iD5H65XouYC7sl2YfYz7IKFYnI6wzz3R6JbobGg8g52T31kR1cPmDc7rHZuz2btOrV44Nmm5UmpA78oGdtfTiIzEBSNXBOuP/AbCpu7J/Xly75FfjG2HSUBFS3OoMkvYoIT1rkLndahMJEsTJPXlxyehZZXGWYTy8uYlmnjCCdMLKuxLdKjs/STpDuHF2U41DR/r90cRwNZ2gkRquahG0VO8XLR1VrUUosdN5iETOXjA3Yhgd4zzIgy2bx29Dg2cPhs0zrqYyecQGvfONeKYflVRQajyUNXpPsw9mLQRJc6I2OjVtsTrcLt1AgMBAAE=";
 static final String HMAC_KEY="15960080267cfa3877dce327aa0cfbbaadf8dc4ff47a3cad680e865bdbc18000";
 static byte[] ascii(String s){return s.getBytes(StandardCharsets.US_ASCII);}
 static byte[] url64(String s){return Base64.getUrlDecoder().decode(s);}
 static JsonObject signed(String json)throws Exception{
  JsonObject o=JsonParser.parseString(json).getAsJsonObject();
  if(!o.get("alg").getAsString().equals("RS256"))throw new Exception("algorithm");
  String p=o.get("payload").getAsString();
  Signature sig=Signature.getInstance("SHA256withRSA");
  sig.initVerify(KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(Base64.getDecoder().decode(PUBLIC_KEY))));
  sig.update(ascii(p));if(!sig.verify(url64(o.get("signature").getAsString())))throw new Exception("signature");
  return JsonParser.parseString(new String(url64(p),StandardCharsets.UTF_8)).getAsJsonObject();
 }
 public static void main(String[] args)throws Exception{
  String text=Files.readString(Path.of(args[1]),StandardCharsets.UTF_8).strip();
  if(args[0].equals("manifest")){System.out.print(signed(text));return;}
  if(!args[0].equals("outer")||!text.startsWith("SPCF1\n"))throw new Exception("format");
  JsonObject o=signed(text.substring(6));
  if(o.get("iterations").getAsInt()!=600000||!o.get("key_id").getAsString().equals("a8d4e7d79e33bcb8"))throw new Exception("parameters");
  Mac mac=Mac.getInstance("HmacSHA256");mac.init(new SecretKeySpec(HexFormat.of().parseHex(HMAC_KEY),"HmacSHA256"));
  mac.update(ascii("SPEICERS_FILE_PASSWORD_V1\0"));
  byte[] h=mac.doFinal("ProteccionSanta$666".getBytes(StandardCharsets.UTF_8));
  char[] password=Base64.getUrlEncoder().withoutPadding().encodeToString(h).toCharArray();
  byte[] salt=url64(o.get("salt").getAsString());
  byte[] key=SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256").generateSecret(new PBEKeySpec(password,salt,600000,256)).getEncoded();
  Cipher cipher=Cipher.getInstance("AES/GCM/NoPadding");
  cipher.init(Cipher.DECRYPT_MODE,new SecretKeySpec(key,"AES"),new GCMParameterSpec(128,url64(o.get("nonce").getAsString())));
  cipher.updateAAD(ascii("SPCF1|netfree.mx.store|servers|a8d4e7d79e33bcb8|600000|"+o.get("salt").getAsString()));
  System.out.write(cipher.doFinal(url64(o.get("ciphertext").getAsString())));
 }
}

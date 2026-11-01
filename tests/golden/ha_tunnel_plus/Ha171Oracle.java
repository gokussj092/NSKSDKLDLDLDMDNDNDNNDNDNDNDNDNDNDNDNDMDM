import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.MessageDigest;
import java.util.*;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import com.google.gson.*;
/** Independent reproduction of the recovered HA 1.7.1 Java primitives/layout. */
class Ha171Oracle {
 static final String XOR="**rVg7EkL~c2`D[aNn";
 static byte[] crypt(byte[] input,String phrase,int mode)throws Exception{
  byte[] key=Arrays.copyOf(MessageDigest.getInstance("SHA-1").digest(phrase.getBytes(StandardCharsets.UTF_8)),16);
  Cipher c=Cipher.getInstance("AES/ECB/PKCS5Padding");c.init(mode,new SecretKeySpec(key,"AES"));return c.doFinal(input);
 }
 static JsonObject json(byte[] b){return JsonParser.parseString(new String(b,StandardCharsets.UTF_8)).getAsJsonObject();}
 static JsonElement section(JsonElement v){return v.isJsonPrimitive()?JsonParser.parseString(v.getAsString()):v;}
 static String unhide(String v){String x=new String(Base64.getMimeDecoder().decode(v),StandardCharsets.UTF_8);StringBuilder out=new StringBuilder();for(int i=0;i<x.length();i++)out.append((char)(x.charAt(i)^XOR.charAt(i%XOR.length())));return out.toString();}
 public static void main(String[] args)throws Exception{
  if(args.length!=3||!Set.of("catalog","inspect","export").contains(args[0]))
   throw new IllegalArgumentException("catalog|inspect|export INPUT NEW_OUTPUT");
  byte[] in=Files.readAllBytes(Path.of(args[1]));JsonObject document;
  if(args[0].equals("catalog")){
   document=json(in);document.add("servers",section(document.get("servers")));document.add("allowed_apps",section(document.get("allowed_apps")));
   document.add("methods",json(crypt(Base64.getMimeDecoder().decode(document.get("methods").getAsString()),"3A0183FADC903782",Cipher.DECRYPT_MODE)));
  }else{
   document=json(crypt(Base64.getMimeDecoder().decode(new String(in,StandardCharsets.UTF_8)),"8515D40BD04D8C97",Cipher.DECRYPT_MODE));
   if(document.has("profilev5")){
    JsonObject profile=document.getAsJsonObject("profilev5");
    for(String k:new String[]{"connection_mode","custom_payload","custom_sni","custom_host"})profile.addProperty(k,unhide(profile.get(k).getAsString()));
    profile.remove("protextras");document.add("profile",profile);
    document.addProperty("description",document.has("descriptionv5")?document.get("descriptionv5").getAsString():"");
   }
   for(String k:new String[]{"profilev5","profilev4","protextras","descriptionv5"})document.remove(k);
  }
  byte[] plain=new GsonBuilder().disableHtmlEscaping().serializeNulls().create().toJson(document).getBytes(StandardCharsets.UTF_8);
  if(args[0].equals("export"))plain=Base64.getEncoder().encode(crypt(plain,"8515D40BD04D8C97",Cipher.ENCRYPT_MODE));
  Path output=Path.of(args[2]);
  Files.createFile(output,java.nio.file.attribute.PosixFilePermissions.asFileAttribute(
    java.nio.file.attribute.PosixFilePermissions.fromString("rw-------")));
  Files.write(output,plain);
 }
}

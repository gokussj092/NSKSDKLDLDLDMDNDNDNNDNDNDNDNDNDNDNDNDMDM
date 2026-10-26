// Independent JDK producer for B46 v5/v6 and native FLXFLD fields.
import java.nio.file.*;
import java.nio.charset.StandardCharsets;
import java.nio.ByteBuffer;
import java.security.MessageDigest;
import java.util.*;
import java.util.zip.GZIPOutputStream;
import java.io.ByteArrayOutputStream;
import javax.crypto.*;
import javax.crypto.spec.*;
class FlexB46VectorGenerator {
 static byte[] text(String s){return s.getBytes(StandardCharsets.UTF_8);}
 static byte[] cat(byte[]... xs){var o=new ByteArrayOutputStream();for(var x:xs)o.writeBytes(x);return o.toByteArray();}
 static byte[] seq(int n,int len){byte[] b=new byte[len];for(int i=0;i<len;i++)b[i]=(byte)(n+i);return b;}
 static byte[] be(int n){return ByteBuffer.allocate(4).putInt(n).array();}
 static byte[] root=HexFormat.of().parseHex("09c76c0cea3739ed9aac7fb157978b4ce701d81194f7730e45c1a69750dcfd6b");
 static byte[] hmac(byte[] key,byte[] data)throws Exception{var m=Mac.getInstance("HmacSHA256");m.init(new SecretKeySpec(key,"HmacSHA256"));return m.doFinal(data);}
 static byte[] hkdf(byte[] salt,byte[] info)throws Exception{return hmac(hmac(salt,root),cat(info,new byte[]{1}));}
 static byte[] seal(byte[] key,byte[] nonce,byte[] plain,byte[] aad)throws Exception{var c=Cipher.getInstance("AES/GCM/NoPadding");c.init(1,new SecretKeySpec(key,"AES"),new GCMParameterSpec(128,nonce));c.updateAAD(aad);return c.doFinal(plain);}
 static byte[] field(String name,String alias,String value)throws Exception{
  byte[] salt=seq(1,32),nonce=seq(50,12),plain=text(value),binding=text("FlexNet/inner-field/v1\0"+name+"|"+alias);
  byte[] header=cat(text("FLXFLD"),new byte[]{1,1},be(43),salt,nonce,be(plain.length+16));
  byte[] key=hkdf(salt,cat(text("FlexNet/inner-field/v1/generation-1"),binding));
  return cat(header,seal(key,nonce,plain,cat(header,binding)));
 }
 static byte[] gzip(byte[] plain)throws Exception{var o=new ByteArrayOutputStream();try(var g=new GZIPOutputStream(o)){g.write(plain);}return o.toByteArray();}
 static byte[] offline(byte[] plain)throws Exception{
  byte[] key=seq(160,32),nonce=seq(30,12),salt=seq(0,32),wn=seq(60,12),packed=gzip(plain);
  byte[] prefix=cat(text("FLXCFG"),new byte[]{5,1,1},be(46),be(1),seq(80,16));
  byte[] wh=cat(prefix,salt,wn),wk=hkdf(salt,cat(text("FlexNet/v5/offline/wrap/generation-1"),prefix));
  byte[] header=cat(wh,seal(wk,wn,key,wh),nonce,be(packed.length+16));return cat(header,seal(key,nonce,packed,header));
 }
 static String esc(String s){return s.replace("&","&amp;").replace("<","&lt;").replace("\"","&quot;").replace("\r","&#13;").replace("\n","&#10;");}
 public static void main(String[]args)throws Exception{
  Path out=Path.of(args[0]);Files.createDirectories(out);
  String sniAlias="visible.example.invalid",payloadAlias="GET / HTTP/1.1[crlf]Host: visible.example.invalid[crlf][crlf]";
  byte[] sni=field("customSni",sniAlias,"real.example.invalid"),payload=field("proxyPayload",payloadAlias,"GET /safe HTTP/1.1\r\nHost: real.example.invalid\r\n\r\n");
  Files.write(out.resolve("sni.field"),sni);Files.write(out.resolve("sni.binding"),text("FlexNet/inner-field/v1\0customSni|"+sniAlias));
  String route="{\"v\":1,\"fields\":{\"customSni\":{\"a\":\""+sniAlias+"\",\"c\":\""+Base64.getEncoder().encodeToString(sni)+"\"},\"proxyPayload\":{\"a\":\""+payloadAlias+"\",\"c\":\""+Base64.getEncoder().encodeToString(payload)+"\"}}}";
  String xml="<properties><comment>Synthetic B46 日本語</comment><entry key=\"tunnelType\">3</entry><entry key=\"customSni\">"+esc(sniAlias)+"</entry><entry key=\"proxyPayload\">"+esc(payloadAlias)+"</entry><entry key=\"file.routeFields\">1</entry><entry key=\"file.routeData\">"+esc(route)+"</entry><entry key=\"custom.unknown\">keep-me</entry><entry key=\"sshServer\">vpn.example.invalid</entry></properties>";
  byte[] plain=text(xml),packed=gzip(plain),key=seq(160,32),nonce=seq(30,12),offline=offline(plain);
  byte[] oh=cat(text("FLXCFG"),new byte[]{5,2,1},be(46),seq(90,16),nonce,be(packed.length+16));
  byte[] online=cat(oh,seal(key,nonce,packed,oh));
  Files.write(out.resolve("online.flex"),online);Files.write(out.resolve("offline.flex"),offline);
  byte[] challenge=seq(10,32),grant=cat(key,seq(90,16),MessageDigest.getInstance("SHA-256").digest(online),challenge,be(46),new byte[]{2});
  String capture="{\n  \"schema\": \"flexnet-v5-authorized-grant/1\",\n  \"fileSha256\": \""+HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(online))+"\",\n  \"challengeBase64\": \""+Base64.getEncoder().encodeToString(challenge)+"\",\n  \"grantBase64\": \""+Base64.getEncoder().encodeToString(grant)+"\"\n}\n";
  Files.writeString(out.resolve("grant-capture.json"),capture);
  byte[] setup=seq(200,32),vh=cat(text("FLXCFG"),new byte[]{6,1,1},be(46),seq(100,16),nonce,be(offline.length+16));
  Files.write(out.resolve("v6.flex"),cat(vh,seal(setup,nonce,offline,vh)));
  Files.write(out.resolve("profile.xml"),plain);Files.write(out.resolve("file-key.bin"),key);Files.write(out.resolve("offline-key.bin"),setup);
 }
}

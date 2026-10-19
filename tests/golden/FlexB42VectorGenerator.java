import java.nio.file.*;
import java.nio.charset.StandardCharsets;
import java.nio.ByteBuffer;
import java.util.*;
import java.util.zip.GZIPOutputStream;
import java.io.ByteArrayOutputStream;
import java.security.MessageDigest;
import javax.crypto.*;
import javax.crypto.spec.*;

class FlexB42VectorGenerator {
  static byte[] text(String s) {return s.getBytes(StandardCharsets.UTF_8);}
  static byte[] cat(byte[]... arrays) {var out=new ByteArrayOutputStream();for(var a:arrays)out.writeBytes(a);return out.toByteArray();}
  static byte[] seq(int first,int count) {byte[] b=new byte[count];for(int i=0;i<count;i++)b[i]=(byte)(first+i);return b;}
  static byte[] be(int n) {return ByteBuffer.allocate(4).putInt(n).array();}
  static byte[] hmac(byte[] key,byte[] value) throws Exception {var m=Mac.getInstance("HmacSHA256");m.init(new SecretKeySpec(key,"HmacSHA256"));return m.doFinal(value);}
  static byte[] hkdf(byte[] root,byte[] salt,byte[] info) throws Exception {return hmac(hmac(salt,root),cat(info,new byte[]{1}));}
  static byte[] seal(byte[] key,byte[] nonce,byte[] plain,byte[] aad) throws Exception {
    var cipher=Cipher.getInstance("AES/GCM/NoPadding");cipher.init(Cipher.ENCRYPT_MODE,new SecretKeySpec(key,"AES"),new GCMParameterSpec(128,nonce));cipher.updateAAD(aad);return cipher.doFinal(plain);
  }
  static byte[] gzip(byte[] plain) throws Exception {var out=new ByteArrayOutputStream();try(var g=new GZIPOutputStream(out)){g.write(plain);}return out.toByteArray();}
  public static void main(String[] args) throws Exception {
    Path out=Path.of(args[0]);Files.createDirectories(out);
    String xml="<?xml version=\"1.0\" encoding=\"UTF-8\"?><!DOCTYPE properties SYSTEM \"http://java.sun.com/dtd/properties.dtd\"><properties><comment>Synthetic FlexNet 日本語</comment><entry key=\"tunnelType\">3</entry><entry key=\"sshServer\">vpn.example.invalid</entry><entry key=\"sshPort\">443</entry><entry key=\"sshUser\">demo</entry><entry key=\"sshPass\">synthetic-only</entry><entry key=\"proxyPayload\">GET / HTTP/1.1&#13;&#10;Host: example.invalid</entry><entry key=\"custom.unknown\">keep-me</entry><entry key=\"remoteServerSnapshot\">{&quot;name&quot;:&quot;Synthetic&quot;,&quot;host&quot;:&quot;catalog.example.invalid&quot;,&quot;futureField&quot;:{&quot;keep&quot;:true}}</entry></properties>";
    byte[] plain=text(xml),packed=gzip(plain),key=seq(160,32),nonce=seq(30,12);
    byte[] onlineHeader=cat(text("FLXCFG"),new byte[]{5,2,1},be(42),seq(90,16),nonce,be(packed.length+16));
    Files.write(out.resolve("online.flex"),cat(onlineHeader,seal(key,nonce,packed,onlineHeader)));
    byte[] salt=seq(0,32),wrapNonce=seq(50,12),root=HexFormat.of().parseHex("09c76c0cea3739ed9aac7fb157978b4ce701d81194f7730e45c1a69750dcfd6b");
    byte[] first33=cat(text("FLXCFG"),new byte[]{5,1,1},be(42),be(1),seq(80,16));
    byte[] wrapHeader=cat(first33,salt,wrapNonce);
    byte[] wrappingKey=hkdf(root,salt,cat(text("FlexNet/v5/offline/wrap/generation-1"),first33));
    byte[] wrapped=seal(wrappingKey,wrapNonce,key,wrapHeader);
    byte[] offlineHeader=cat(wrapHeader,wrapped,nonce,be(packed.length+16));
    Files.write(out.resolve("offline.flex"),cat(offlineHeader,seal(key,nonce,packed,offlineHeader)));
    StringBuilder servers=new StringBuilder("{\"version\":1,\"serversVersion\":\"synthetic\",\"servers\":[");
    for(int i=0;i<7;i++){if(i>0)servers.append(',');servers.append("{\"id\":\"test-"+i+"\",\"host\":\"server"+i+".example.invalid\",\"unknown\":{\"preserve\":true}}");}
    servers.append("]}");byte[] catalog=text(servers.toString());
    byte[] catalogKey=MessageDigest.getInstance("SHA-256").digest(cat(text("flexnet-builtin-servers-v1\0"),text("cinbdf665$4")));
    Files.write(out.resolve("catalog.dat"),cat(text("FBS1"),nonce,seal(catalogKey,nonce,catalog,text("FBS1"))));
    Files.write(out.resolve("profile.xml"),plain);Files.write(out.resolve("file-key.bin"),key);Files.write(out.resolve("catalog.json"),catalog);
  }
}

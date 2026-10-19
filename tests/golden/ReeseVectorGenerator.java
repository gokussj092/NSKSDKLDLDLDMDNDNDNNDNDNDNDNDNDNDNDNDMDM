import java.nio.file.*;
import java.nio.charset.StandardCharsets;
import java.nio.ByteBuffer;
import java.util.*;
import java.util.zip.Deflater;
import java.io.ByteArrayOutputStream;
import java.security.MessageDigest;
import javax.crypto.*;
import javax.crypto.spec.*;

class ReeseVectorGenerator {
  static byte[] cat(byte[]... arrays) { var out=new ByteArrayOutputStream(); for(var a:arrays)out.writeBytes(a);return out.toByteArray(); }
  static byte[] text(String s) { return s.getBytes(StandardCharsets.UTF_8); }
  static byte[] seq(int start,int n) { byte[] a=new byte[n];for(int i=0;i<n;i++)a[i]=(byte)(start+i);return a; }
  static byte[] be(int n) { return ByteBuffer.allocate(4).putInt(n).array(); }
  static byte[] slice(byte[] x,int a,int b) { return Arrays.copyOfRange(x,a,b); }
  static byte[] hmac(byte[] key,byte[] x) throws Exception { Mac m=Mac.getInstance("HmacSHA256");m.init(new SecretKeySpec(key,"HmacSHA256"));return m.doFinal(x); }
  static byte[] kdf(byte[] pw,byte[] salt,int rounds,int size) throws Exception {
    Mac m=Mac.getInstance("HmacSHA256");m.init(new SecretKeySpec(pw,"HmacSHA256"));
    var out=new ByteArrayOutputStream();
    for(int b=1;out.size()<size;b++) {
      byte[] u=m.doFinal(cat(salt,be(b))), t=u.clone();
      for(int n=1;n<rounds;n++){u=m.doFinal(u);for(int j=0;j<32;j++)t[j]^=u[j];}
      out.writeBytes(t);
    }
    return Arrays.copyOf(out.toByteArray(),size);
  }
  static byte[] aes(byte[] key,byte[] iv,byte[] body,boolean gcm,byte[] aad) throws Exception {
    Cipher c=Cipher.getInstance(gcm?"AES/GCM/NoPadding":"AES/CBC/PKCS5Padding");
    if(gcm)c.init(Cipher.ENCRYPT_MODE,new SecretKeySpec(key,"AES"),new GCMParameterSpec(128,iv));
    else c.init(Cipher.ENCRYPT_MODE,new SecretKeySpec(key,"AES"),new IvParameterSpec(iv));
    if(gcm&&aad.length>0)c.updateAAD(aad);
    return c.doFinal(body);
  }
  static byte[] stream(byte[] seed,int size) throws Exception {
    var out=new ByteArrayOutputStream();var digest=MessageDigest.getInstance("SHA-256");
    for(int n=0;out.size()<size;n++)out.writeBytes(digest.digest(cat(seed,be(n))));
    return Arrays.copyOf(out.toByteArray(),size);
  }
  static byte[] shuffle(byte[] body,byte[] seed) throws Exception {
    int[] order=new int[body.length];for(int i=0;i<order.length;i++)order[i]=i;
    byte[] random=stream(seed,body.length*4);int at=0;
    for(int i=order.length-1;i>0;i--){long value=ByteBuffer.wrap(random,at,4).getInt()&0xffffffffL;at+=4;int j=(int)(value%(i+1));int t=order[i];order[i]=order[j];order[j]=t;}
    byte[] out=new byte[body.length];for(int i=0;i<body.length;i++)out[order[i]]=body[i];return out;
  }
  static byte[] compress(byte[] plain) {
    Deflater d=new Deflater(1,true);d.setInput(plain);d.finish();var out=new ByteArrayOutputStream();byte[] buf=new byte[4096];
    while(!d.finished())out.write(buf,0,d.deflate(buf));d.end();return out.toByteArray();
  }
  static byte[] padding(byte[] packed,boolean sized) { return cat(new byte[]{3},seq(50,19),sized?be(packed.length):new byte[0],packed,sized?seq(150,32):new byte[0]); }
  static void vector(Path out,String name,byte[] packed,int version,int variant,int flags,String hwid,String password) throws Exception {
    byte[] salt=seq(0,16),nonce=seq(16,12),iv=seq(40,16),innerIv=seq(60,16),file;
    if(version==5) {
      String material="REESE-CUSTOM/RSE5|"+((flags&1)!=0?hwid:"")+"|"+((variant==0xc3||(flags&2)!=0)?password:"");
      if(variant==0xc4&&(flags&4)!=0)material+="|SIG:D834BF8D60BFEA09A80A51CCD1A77DE3EF966E7833EBB2D0B8DC1F750E38BBA7";
      byte[] header=cat(new byte[]{(byte)0xa7,0x19,(byte)0xd2,0x4c,(byte)variant,(byte)flags},salt,nonce);
      file=cat(header,aes(kdf(text(material),salt,32768,32),nonce,padding(packed,true),true,header));
    } else {
      String selector=hwid.isEmpty()?"0000":HexFormat.of().formatHex(Arrays.copyOf(MessageDigest.getInstance("SHA-256").digest(text(hwid)),2));
      if(version==4){
        byte[] body=padding(packed,false),header=cat(text("RSE4"),salt,nonce,text(selector),be(body.length));
        file=cat(header,aes(kdf(text("REESE-CUSTOM/RSE4|"+hwid+"|"+password),salt,600000,32),nonce,body,true,header));
      } else {
        String material="REESE-CUSTOM/config-envelope/v1|"+hwid+(password.isEmpty()?"":"|"+password);
        int rounds=version==1?80000:version==2?140000:24000;
        byte[] keys=kdf(text(material),salt,rounds,version==1?128:192);
        byte[] gcm=aes(slice(keys,0,32),nonce,version==1?packed:padding(packed,false),true,new byte[0]);
        byte[] body=aes(slice(keys,32,64),iv,gcm,false,new byte[0]);
        byte[] mask=stream(slice(keys,64,96),body.length);for(int i=0;i<body.length;i++)body[i]^=mask[i];
        if(version>=2)body=shuffle(aes(slice(keys,128,160),innerIv,body,false,new byte[0]),slice(keys,160,192));
        byte[] header=cat(text("RSE"+version),salt,nonce,iv,version>=2?innerIv:new byte[0],text(selector),be(body.length));
        byte[] authenticated=cat(header,body);file=cat(authenticated,hmac(slice(keys,96,128),authenticated));
      }
    }
    Files.write(out.resolve(name+".bin"),file);
  }
  public static void main(String[] args) throws Exception {
    Path out=Path.of(args[1]);Files.createDirectories(out);byte[] packed=compress(Files.readAllBytes(Path.of(args[0])));
    for(int v=1;v<=4;v++){
      vector(out,"rse"+v+"-open",packed,v,0,0,"","");
      vector(out,"rse"+v+"-protected",packed,v,0,0,"RC-TEST-1234-5678-ABCD","synthetic-ç鍵");
    }
    vector(out,"rse5-c3-open",packed,5,0xc3,0,"","");
    vector(out,"rse5-c3-protected",packed,5,0xc3,1,"RC-TEST-1234-5678-ABCD","synthetic-ç鍵");
    for(int flags:new int[]{0,1,2,3,4,7})vector(out,"rse5-c4-flags"+flags,packed,5,0xc4,flags,(flags&1)!=0?"RC-TEST-1234-5678-ABCD":"",(flags&2)!=0?"synthetic-ç鍵":"");
  }
}

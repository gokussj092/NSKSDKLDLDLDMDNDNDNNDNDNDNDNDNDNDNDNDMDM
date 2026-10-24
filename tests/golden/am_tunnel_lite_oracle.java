import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.*;

/** Independent DataInput/OutputStream modified UTF-8 and original PUtils XOR. */
class am_tunnel_lite_oracle {
 static final byte[] KEY={0x34,0x25,0x50,0x64,0x58,0x63,0x68,0x3e,0x66,0x6b,0x50,0x5d};
 static byte[] xor(byte[] raw){byte[] out=raw.clone();for(int i=0;i<out.length;i++)out[i]^=KEY[i%KEY.length];return out;}
 static byte[] mutf(String text)throws Exception{var out=new ByteArrayOutputStream();new DataOutputStream(out).writeUTF(text);return Arrays.copyOfRange(out.toByteArray(),2,out.size());}
 static String text(byte[] raw)throws Exception{var out=new ByteArrayOutputStream();var stream=new DataOutputStream(out);stream.writeShort(raw.length);stream.write(raw);return new DataInputStream(new ByteArrayInputStream(out.toByteArray())).readUTF();}
 public static void main(String[]args)throws Exception{
  var reader=new BufferedReader(new InputStreamReader(System.in,StandardCharsets.UTF_8));String line;
  while((line=reader.readLine())!=null){String[] p=line.split("\t",2);byte[] in=Base64.getDecoder().decode(p[1]);byte[] out;
   if(p[0].equals("encrypt"))out=HexFormat.of().formatHex(xor(mutf(new String(in,StandardCharsets.UTF_8)))).getBytes(StandardCharsets.US_ASCII);
   else if(p[0].equals("raw"))out=xor(in);
   else if(p[0].equals("mutf"))out=mutf(new String(in,StandardCharsets.UTF_8));
   else if(p[0].equals("decrypt"))out=text(xor(HexFormat.of().parseHex(new String(in,StandardCharsets.US_ASCII)))).getBytes(StandardCharsets.UTF_8);
   else throw new IllegalArgumentException("mode");
   System.out.println(Base64.getEncoder().encodeToString(out));
  }
 }
}

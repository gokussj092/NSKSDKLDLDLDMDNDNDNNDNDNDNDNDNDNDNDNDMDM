import java.nio.*;import java.nio.charset.*;import java.nio.file.*;import java.util.*;
import javax.crypto.*;import javax.crypto.spec.*;
/** Independent JCA transcript of the statically traced ARMv7 KDF and fields. */
class SpeigoOracle {
 static byte[] hex(String x){return HexFormat.of().parseHex(x);}
 static byte[] utf(String x){return x.getBytes(StandardCharsets.UTF_8);}
 static byte[] join(byte[]...xs){int n=0;for(byte[] x:xs)n+=x.length;byte[] r=new byte[n];n=0;for(byte[]x:xs){System.arraycopy(x,0,r,n,x.length);n+=x.length;}return r;}
 static byte[] le(int x){return ByteBuffer.allocate(4).order(ByteOrder.LITTLE_ENDIAN).putInt(x).array();}
 static byte[] mac(byte[] key,byte[] message)throws Exception{Mac m=Mac.getInstance("HmacSHA256");m.init(new SecretKeySpec(key,"HmacSHA256"));return m.doFinal(message);}
 static final byte[] ROOT=hex("e973cfb02d8a0fc2102cd8a0351c199c1cba7c04a507d082fa68231bea2f4fb3"),CTX=hex("af9d380863dc5c05851192e82d6fda880ce0346f877ab0c093000c7dbe372194");
 static byte[] key(int purpose,int index,byte[] meta)throws Exception{
  byte[] p={(byte)purpose};byte[] base=mac(ROOT,join(utf("SVR5B2-BASE-KDF-V1\0"),hex("e16bc172948f3d5add29a76b8f30461e"),le(112),p,CTX));
  return mac(base,join(utf("SVR5B2-REC-KDF-V1\0"),hex("0f34b5982d7ae6c1"),le(112),le(index),p,meta,CTX));
 }
 static String strict(byte[] b)throws Exception{return StandardCharsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT).onUnmappableCharacter(CodingErrorAction.REPORT).decode(ByteBuffer.wrap(b)).toString();}
 static String rotate(String s,int shift){StringBuilder r=new StringBuilder();for(char c:s.toCharArray()){int base=Character.isUpperCase(c)?65:97;r.append(Character.isLetter(c)?(char)((c+shift-base)%26+base):c);}return r.toString();}
 static byte[] field(String s,boolean seal)throws Exception{
  if(s.isEmpty())return utf(s);byte[] raw=seal?new byte[16]:Base64.getUrlDecoder().decode(s);
  Cipher c=Cipher.getInstance("AES/CBC/PKCS5Padding");c.init(seal?1:2,new SecretKeySpec(Arrays.copyOf(utf("Diablo2105AZW8Es"),32),"AES"),new IvParameterSpec(Arrays.copyOf(raw,16)));
  if(!seal)return utf(rotate(strict(c.doFinal(Arrays.copyOfRange(raw,16,raw.length))),21));
  return utf(Base64.getUrlEncoder().withoutPadding().encodeToString(join(raw,c.doFinal(utf(rotate(s,5))))));
 }
 public static void main(String[] args)throws Exception{
  for(String line:Files.readAllLines(Path.of(args[0]),StandardCharsets.UTF_8)){
   String[] p=line.split("\t",-1);byte[] out;
   if(p[0].equals("key"))out=key(Integer.parseInt(p[1]),Integer.parseInt(p[2]),Base64.getDecoder().decode(p[3]));
   else out=field(strict(Base64.getDecoder().decode(p[1])),p[0].equals("seal"));
   System.out.println(Base64.getEncoder().encodeToString(out));
  }
 }
}

import java.io.*;
import java.nio.*;
import java.nio.charset.*;
import java.util.*;
// Independent Java base64/UTF-8 field oracle matching KHAM g72.m.
class FieldOracle {
 public static void main(String[] args)throws Exception {
  var r=new BufferedReader(new InputStreamReader(System.in,StandardCharsets.UTF_8));String line;
  while((line=r.readLine())!=null){
   String field=new String(Base64.getDecoder().decode(line),StandardCharsets.US_ASCII);
   byte[] plain=Base64.getMimeDecoder().decode(field);
   StandardCharsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT).decode(ByteBuffer.wrap(plain));
   System.out.println(Base64.getEncoder().encodeToString(plain));
  }
 }
}

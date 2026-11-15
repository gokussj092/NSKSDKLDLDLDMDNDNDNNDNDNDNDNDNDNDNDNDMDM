import java.nio.*;
import java.nio.file.*;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.zip.CRC32;
import javax.crypto.*;
import javax.crypto.spec.*;

/** Independent JDK PBKDF2/GCM + Java Properties oracle for synthetic inputs. */
class OpenOracle {
  static String b64(byte[] b) { return Base64.getEncoder().encodeToString(b); }
  public static void main(String[] args) throws Exception {
    byte[] xml=Files.readAllBytes(Path.of(args[0]));
    Properties p=new Properties();p.loadFromXML(new java.io.ByteArrayInputStream(xml));
    byte[] salt=new byte[32],nonce=new byte[12];
    for(int i=0;i<salt.length;i++)salt[i]=(byte)i;
    for(int i=0;i<nonce.length;i++)nonce[i]=(byte)(i+61);
    char[] password="f3a91c4e2d7b05869e4f1a3c8d2e6b07a5c9f2e14d8b3a76e0f5c1d9b4a72e3f".toCharArray();
    byte[] key=SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256").generateSecret(new PBEKeySpec(password,salt,100000,256)).getEncoded();
    Cipher cipher=Cipher.getInstance("AES/GCM/NoPadding");
    cipher.init(Cipher.ENCRYPT_MODE,new SecretKeySpec(key,"AES"),new GCMParameterSpec(128,nonce));
    byte[] packed=(b64(salt)+"."+b64(nonce)+"."+b64(cipher.doFinal(xml))).getBytes(StandardCharsets.US_ASCII);
    CRC32 crc=new CRC32();crc.update(packed);
    ByteBuffer opl=ByteBuffer.allocate(12+packed.length).order(ByteOrder.LITTLE_ENDIAN);
    opl.put(new byte[]{'O','P','L',2}).putInt(packed.length^-1481390639).putInt((int)crc.getValue());
    for(int i=0;i<packed.length;i++) {
      int shift=i%8,rotate=((195<<shift)|(195>>>(8-shift)))&255;
      opl.put((byte)(packed[i]^rotate^(i&255)));
    }
    int[] seed={7,6,11,12,122,7,125,7,123,123,122,13,9,9,11,9,8,121,124,13,125,121,10,9,14,8,13,6,9,15};
    byte[] legacyKey=new byte[32];
    for(int i=0;i<32;i++)legacyKey[i]=(byte)((i*29)%255+1);
    for(int i=0;i<seed.length;i++) {
      int n=legacyKey[i%32]&255;
      legacyKey[i%32]=(byte)(((n>>>5)|(n<<3))^((i+7)*(seed[i]^63))^((i*13)%255));
    }
    for(int turn=0;turn<3;turn++)for(int i=0;i<31;i++)legacyKey[i]=(byte)((legacyKey[i]&255)^((legacyKey[i]&255)%7+(legacyKey[i+1]&255)));
    int sequence=0x12345678;
    ByteBuffer legacy=ByteBuffer.allocate(8+xml.length).putInt(sequence).putInt(xml.length);
    for(int i=0;i<xml.length;i++) {
      int value=(xml[i]&255)^(legacyKey[i%32]&255)^((sequence>>>((i%4)*8))&255);
      legacy.put((byte)(((value>>>5)|(value<<3))^((i*7+13)&255)));
    }
    System.out.println(b64(packed));System.out.println(b64(opl.array()));
    System.out.println(b64(b64(legacy.array()).getBytes(StandardCharsets.US_ASCII)));
  }
}

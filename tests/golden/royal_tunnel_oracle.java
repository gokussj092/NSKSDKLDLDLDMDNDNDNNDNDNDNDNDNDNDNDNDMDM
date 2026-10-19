import java.nio.file.*;import java.util.*;import java.nio.*;import javax.crypto.*;import javax.crypto.spec.*;
class RoyalFormatOracle {
static byte[] hex(String s){return HexFormat.of().parseHex(s);}
static final byte[] K=hex("e385a4e385a4e385a4e385a4e385a4e3");
static final byte[] CFB=hex("974f2a3d5e5c0d50ca2c3e8aae1c4f79ddccf43cef90f9984a7e09fdc09bc482");
static final byte[] CIV=hex("4e6a2c8153d9b4a7903f685ca1ef2479");
static final byte[] TW=hex("6438383065643332393166393664393436346132633933356538323938333766");
static final byte[] TIV=hex("3c7f1a9d55e3c0b28e216d4a97ff1362");
static final byte[] N=hex("0123456789abcdef1032547698badcfe554433221100aabbccddeeff99887766");
public static int[] E(byte[] bArr) {
        int[] iArr = new int[(bArr.length & 3) == 0 ? bArr.length >>> 2 : (bArr.length >>> 2) + 1];
        int length = bArr.length;
        for (int i = 0; i < length; i++) {
            int i2 = i >>> 2;
            iArr[i2] = iArr[i2] | ((bArr[i] & 255) << ((i & 3) << 3));
        }
        return iArr;
    }
public static int a(int i, int i2, int i3, int i4, int i5, int[] iArr) {
        return ((i ^ i2) + (iArr[(i4 & 3) ^ i5] ^ i3)) ^ (((i3 >>> 5) ^ (i2 << 2)) + ((i2 >>> 3) ^ (i3 << 4)));
    }
public static final byte[] q(byte[] bArr, byte[] bArr2) {
        if (bArr.length == 0) {
            return bArr;
        }
        int[] iArrE = E(bArr);
        if (bArr2.length != 16) {
            byte[] bArr3 = new byte[16];
            if (bArr2.length < 16) {
                System.arraycopy(bArr2, 0, bArr3, 0, bArr2.length);
            } else {
                System.arraycopy(bArr2, 0, bArr3, 0, 16);
            }
            bArr2 = bArr3;
        }
        int[] iArrE2 = E(bArr2);
        int length = iArrE.length;
        int i = length - 1;
        if (i >= 1) {
            int i2 = (52 / length) + 6;
            int iA = iArrE[0];
            for (int i3 = i2 * (-1703701580); i3 != 0; i3 -= -1703701580) {
                int i4 = (i3 >>> 2) & 3;
                int iA2 = iA;
                int i5 = i;
                while (i5 > 0) {
                    iA2 = iArrE[i5] - a(i3, iA2, iArrE[i5 - 1], i5, i4, iArrE2);
                    iArrE[i5] = iA2;
                    i5--;
                }
                iA = iArrE[0] - a(i3, iA2, iArrE[i], i5, i4, iArrE2);
                iArrE[0] = iA;
            }
        }
        int length2 = iArrE.length << 2;
        int i6 = iArrE[iArrE.length - 1];
        int i7 = length2 - 4;
        if (i6 < length2 - 7 || i6 > i7) {
            return null;
        }
        byte[] bArr4 = new byte[i6];
        for (int i8 = 0; i8 < i6; i8++) {
            bArr4[i8] = (byte) (iArrE[i8 >>> 2] >>> ((i8 & 3) << 3));
        }
        return bArr4;
    }
static byte[] encXX(byte[] plain){
 int[] v=Arrays.copyOf(E(plain),((plain.length+3)/4)+1);v[v.length-1]=plain.length;
 int[] k=E(K);int sum=0,z=v[v.length-1];int rounds=6+52/v.length;
 for(int round=0;round<rounds;round++){
  sum+=-1703701580;int e=(sum>>>2)&3;int pos;
  for(pos=0;pos<v.length-1;pos++){int y=v[pos+1];v[pos]+=a(sum,y,z,pos,e,k);z=v[pos];}
  int y=v[0];v[pos]+=a(sum,y,z,pos,e,k);z=v[pos];
 }
 ByteBuffer buf=ByteBuffer.allocate(v.length*4).order(ByteOrder.LITTLE_ENDIAN);for(int word:v)buf.putInt(word);return buf.array();
}
static byte[] crypto(String mode,byte[] value,boolean enc,byte[] key,byte[] iv)throws Exception{
 Cipher cipher=Cipher.getInstance(mode);cipher.init(enc?1:2,new SecretKeySpec(key,"AES"),mode.contains("GCM")?new GCMParameterSpec(128,iv):new IvParameterSpec(iv));return cipher.doFinal(value);
}
public static void main(String[] args)throws Exception{
 for(String line:Files.readAllLines(Path.of(args[0]))){
  String[] part=line.split("\t",-1);String mode=part[0];byte[] data=Base64.getDecoder().decode(part[1]);byte[] out;
  switch(mode){
   case "xxd":out=q(data,K);break;case "xxe":out=encXX(data);break;
   case "cfbd":case "cfbe":out=crypto("AES/CFB/NoPadding",data,mode.endsWith("e"),CFB,CIV);break;
   case "twkd":case "twke":out=crypto("AES/CBC/PKCS5Padding",data,mode.endsWith("e"),TW,TIV);break;
   case "gcmenc":case "cbcen":
    byte[] iv=new byte[mode.equals("gcmenc")?12:16];for(int i=0;i<iv.length;i++)iv[i]=(byte)i;
    byte[] body=crypto(mode.equals("gcmenc")?"AES/GCM/NoPadding":"AES/CBC/PKCS5Padding",data,true,N,iv);
    out=new byte[iv.length+body.length];System.arraycopy(iv,0,out,0,iv.length);System.arraycopy(body,0,out,iv.length,body.length);break;
   default:throw new Exception("bad command");
  }
  System.out.println(Base64.getEncoder().encodeToString(out));
 }
}
}
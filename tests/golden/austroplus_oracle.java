/* APK 13.0.1 original m83.a/i/j/n, ys.h, o8.a/b and wc0.k/l.
 * Android Base64 calls are adapted to JDK; checked throws declarations only
 * are widened for javac. Reference XXTEA encryption is the inverse used only
 * to produce fake catalog fixtures. No Python decoder is imported.
 * java tests/golden/austroplus_oracle.java commands.tsv
 */
import java.nio.file.*;import java.nio.charset.*;import java.nio.*;import java.util.*;
import java.security.*;import javax.crypto.*;import javax.crypto.spec.*;
class AustroPlusOracle {
static final byte[] KEY="AustroPlusVPN_GenPass@2244".getBytes(StandardCharsets.UTF_8);
static byte[] encXX(byte[] plain){
 int[] v=Arrays.copyOf(OriginalXXTEA.n(plain),((plain.length+3)/4)+1);v[v.length-1]=plain.length;
 int[] k=OriginalXXTEA.n(Arrays.copyOf(KEY,16));int sum=0,z=v[v.length-1];int rounds=6+52/v.length;
 for(int round=0;round<rounds;round++){
  sum+=0x9e3779b9;int e=(sum>>>2)&3;int pos;
  for(pos=0;pos<v.length-1;pos++){int y=v[pos+1];v[pos]+=OriginalXXTEA.a(sum,y,z,pos,k,e);z=v[pos];}
  int y=v[0];v[pos]+=OriginalXXTEA.a(sum,y,z,pos,k,e);z=v[pos];
 }
 ByteBuffer buf=ByteBuffer.allocate(v.length*4).order(ByteOrder.LITTLE_ENDIAN);for(int word:v)buf.putInt(word);return buf.array();
}
public static void main(String[] args)throws Exception{
 for(String line:Files.readAllLines(Path.of(args[0]))){
  String[] part=line.split("\t",-1);byte[] data=java.util.Base64.getDecoder().decode(part[1]);String value=new String(data,StandardCharsets.UTF_8);byte[] out;
  switch(part[0]){
   case "xxd":out=OriginalXXTEA.i(data,KEY);break;
   case "xxe":out=encXX(data);break;
   case "xor":out=OriginalXOR.h(value).getBytes(StandardCharsets.UTF_8);break;
   case "double":out=OriginalBase64.k(value).getBytes(StandardCharsets.UTF_8);break;
   case "doublee":out=OriginalBase64.l(value).getBytes(StandardCharsets.UTF_8);break;
   case "gcmd":out=OriginalFiles.a(value).getBytes(StandardCharsets.UTF_8);break;
   case "gcme":out=OriginalFiles.b(value).getBytes(StandardCharsets.UTF_8);break;
   default:throw new IllegalArgumentException("Unknown mode");
  }
  if(out==null)throw new IllegalArgumentException("Rejected ciphertext");
  System.out.println(java.util.Base64.getEncoder().encodeToString(out));
 }
}
}
class Base64 {
static byte[] decode(String s,int flags){return java.util.Base64.getDecoder().decode(s.replaceAll("\\s", ""));}
static byte[] decode(byte[] s,int flags){return decode(new String(s,StandardCharsets.US_ASCII),flags);}
static String encodeToString(byte[] data,int flags){return new String(encode(data,flags),StandardCharsets.US_ASCII);}
static byte[] encode(byte[] data,int flags){
 if(flags==2)return java.util.Base64.getEncoder().encode(data);
 if(data.length==0)return new byte[0];
 String s=java.util.Base64.getMimeEncoder(76,new byte[]{10}).encodeToString(data)+"\n";return s.getBytes(StandardCharsets.US_ASCII);
}
}
class OriginalXXTEA {
    public static int a(int i2, int i3, int i4, int i5, int[] iArr, int i6) {
        return ((i2 ^ i3) + (iArr[(i5 & 3) ^ i6] ^ i4)) ^ (((i4 >>> 5) ^ (i3 << 2)) + ((i3 >>> 3) ^ (i4 << 4)));
    }
    public static byte[] i(byte[] bArr, byte[] bArr2) {
        if (bArr == null || bArr.length == 0) {
            return bArr;
        }
        int[] iArrN = n(bArr);
        byte[] bArr3 = new byte[16];
        if (bArr2 != null) {
            System.arraycopy(bArr2, 0, bArr3, 0, Math.min(bArr2.length, 16));
        }
        int[] iArrN2 = n(bArr3);
        int length = iArrN.length;
        int i2 = length - 1;
        if (i2 >= 1) {
            int i3 = iArrN[0];
            int i4 = ((52 / length) + 6) * (-1640531527);
            while (i4 != 0) {
                int i5 = (i4 >>> 2) & 3;
                int i6 = i2;
                while (i6 > 0) {
                    int i7 = i4;
                    int iA = iArrN[i6] - a(i7, i3, iArrN[i6 - 1], i6, iArrN2, i5);
                    iArrN[i6] = iA;
                    i6--;
                    i4 = i7;
                    i3 = iA;
                }
                int i8 = i4;
                int iA2 = iArrN[0] - a(i8, i3, iArrN[i2], 0, iArrN2, i5);
                iArrN[0] = iA2;
                i4 = 1640531527 + i8;
                i3 = iA2;
            }
        }
        int length2 = iArrN.length << 2;
        int i9 = iArrN[iArrN.length - 1];
        int i10 = length2 - 4;
        if (i9 < length2 - 7 || i9 > i10) {
            return null;
        }
        byte[] bArr4 = new byte[i9];
        for (int i11 = 0; i11 < i9; i11++) {
            bArr4[i11] = (byte) (iArrN[i11 >>> 2] >>> ((i11 & 3) << 3));
        }
        return bArr4;
    }
    public static String j(String str, String str2) {
        if (str == null || str2 == null) {
            return null;
        }
        try {
            byte[] bArrDecode = java.util.Base64.getDecoder().decode(str);
            Charset charset = StandardCharsets.UTF_8;
            byte[] bArrI = i(bArrDecode, str2.getBytes(charset));
            if (bArrI == null) {
                return null;
            }
            return new String(bArrI, charset);
        } catch (IllegalArgumentException unused) {
            return null;
        }
    }
    public static int[] n(byte[] bArr) {
        int[] iArr = new int[(bArr.length + 3) >>> 2];
        for (int i2 = 0; i2 < bArr.length; i2++) {
            int i3 = i2 >>> 2;
            iArr[i3] = iArr[i3] | ((bArr[i2] & 255) << ((i2 & 3) << 3));
        }
        return iArr;
    }
}
class OriginalXOR {static final byte[] d={66,97,115,101,90,104};
    public static String h(String str) {
        if (str == null) {
            return null;
        }
        try {
            byte[] bArrDecode = java.util.Base64.getDecoder().decode(str);
            byte[] bArr = d;
            byte[] bArr2 = new byte[bArrDecode.length];
            for (int i2 = 0; i2 < bArrDecode.length; i2++) {
                bArr2[i2] = (byte) (bArrDecode[i2] ^ bArr[i2 % 6]);
            }
            return new String(bArr2, StandardCharsets.UTF_8);
        } catch (IllegalArgumentException unused) {
            return null;
        }
    }
}
class OriginalFiles {
    public static String a(String str) throws Exception {
        byte[] bArrDecode = Base64.decode(str, 2);
        byte[] bArr = new byte[12];
        System.arraycopy(bArrDecode, 0, bArr, 0, 12);
        int length = bArrDecode.length - 12;
        byte[] bArr2 = new byte[length];
        System.arraycopy(bArrDecode, 12, bArr2, 0, length);
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec gCMParameterSpec = new GCMParameterSpec(128, bArr);
        String string = "AustroPlus-VPN-File-Secret-Key-!";
        Charset charset = StandardCharsets.UTF_8;
        cipher.init(2, new SecretKeySpec(string.getBytes(charset), "AES"), gCMParameterSpec);
        return new String(cipher.doFinal(bArr2), charset);
    }
    public static String b(String str) throws Exception {
        byte[] bArr = new byte[12];
        new SecureRandom().nextBytes(bArr);
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec gCMParameterSpec = new GCMParameterSpec(128, bArr);
        String string = "AustroPlus-VPN-File-Secret-Key-!";
        Charset charset = StandardCharsets.UTF_8;
        cipher.init(1, new SecretKeySpec(string.getBytes(charset), "AES"), gCMParameterSpec);
        byte[] bArrDoFinal = cipher.doFinal(str.getBytes(charset));
        byte[] bArr2 = new byte[bArrDoFinal.length + 12];
        System.arraycopy(bArr, 0, bArr2, 0, 12);
        System.arraycopy(bArrDoFinal, 0, bArr2, 12, bArrDoFinal.length);
        return Base64.encodeToString(bArr2, 2);
    }
}
class OriginalBase64 {
    public static String k(String str) {
        return new String(Base64.decode(new String(Base64.decode(str.getBytes(), 0)).getBytes(), 0));
    }
    public static String l(String str) {
        return new String(Base64.encode(new String(Base64.encode(str.getBytes(), 0)).getBytes(), 0));
    }
}

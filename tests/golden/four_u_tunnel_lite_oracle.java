import java.io.*;import java.nio.file.*;import java.util.*;import java.nio.charset.StandardCharsets;
class FourUGoldenOracle {
 public static void main(String[] args)throws Exception {
  for(String line:Files.readAllLines(Path.of(args[0]))){
   String[] fields=line.split("\t",-1);byte[] input=Base64.getDecoder().decode(fields[1]),out;
   switch(fields[0]){
    case "enc":out=AbstractC0282Km.d(input,AbstractC0282Km.a.getBytes(StandardCharsets.UTF_8));break;
    case "dec":out=AbstractC0282Km.b(input,AbstractC0282Km.a.getBytes(StandardCharsets.UTF_8));break;
    case "mutf":
     ByteArrayOutputStream buffer=new ByteArrayOutputStream();new DataOutputStream(buffer).writeUTF(new String(input,StandardCharsets.UTF_8));
     out=Arrays.copyOfRange(buffer.toByteArray(),2,buffer.size());break;
    default:throw new Exception("invalid operation");
   }
   System.out.println(Base64.getEncoder().encodeToString(out));
  }
 }
}



/* JADX INFO: renamed from: Km, reason: case insensitive filesystem */
/* JADX INFO: loaded from: classes2.dex */
abstract class AbstractC0282Km {
    public static final String a = "Princie!";

    public static int a(int i, int i2, int i3, int i4, int i5, int[] iArr) {
        return ((i ^ i2) + (iArr[(i4 & 3) ^ i5] ^ i3)) ^ (((i3 >>> 5) ^ (i2 << 2)) + ((i2 >>> 3) ^ (i3 << 4)));
    }

    public static final byte[] b(byte[] bArr, byte[] bArr2) {
        if (bArr.length == 0) {
            return bArr;
        }
        int[] iArrG = g(bArr, false);
        if (bArr2.length != 16) {
            byte[] bArr3 = new byte[16];
            System.arraycopy(bArr2, 0, bArr3, 0, bArr2.length < 16 ? bArr2.length : 16);
            bArr2 = bArr3;
        }
        int[] iArrG2 = g(bArr2, false);
        int length = iArrG.length;
        int i = length - 1;
        if (i >= 1) {
            int i2 = (52 / length) + 6;
            int iA = iArrG[0];
            for (int i3 = i2 * (-1638454863); i3 != 0; i3 -= -1638454863) {
                int i4 = (i3 >>> 2) & 3;
                int iA2 = iA;
                int i5 = i;
                while (i5 > 0) {
                    iA2 = iArrG[i5] - a(i3, iA2, iArrG[i5 - 1], i5, i4, iArrG2);
                    iArrG[i5] = iA2;
                    i5--;
                }
                iA = iArrG[0] - a(i3, iA2, iArrG[i], i5, i4, iArrG2);
                iArrG[0] = iA;
            }
        }
        return f(iArrG, true);
    }

    public static final String c(String str, String str2) {
        byte[] bArrB;
        try {
            try {
                bArrB = b(java.util.Base64.getDecoder().decode(str), str2.getBytes("UTF-8"));
            } catch (UnsupportedEncodingException unused) {
                bArrB = null;
            }
            if (bArrB == null) {
                return null;
            }
            return new String(bArrB, "UTF-8");
        } catch (UnsupportedEncodingException unused2) {
            return null;
        }
    }

    public static final byte[] d(byte[] bArr, byte[] bArr2) {
        if (bArr.length == 0) {
            return bArr;
        }
        int[] iArrG = g(bArr, true);
        if (bArr2.length != 16) {
            byte[] bArr3 = new byte[16];
            System.arraycopy(bArr2, 0, bArr3, 0, bArr2.length < 16 ? bArr2.length : 16);
            bArr2 = bArr3;
        }
        int[] iArrG2 = g(bArr2, false);
        int length = iArrG.length;
        int i = length - 1;
        if (i >= 1) {
            int i2 = (52 / length) + 6;
            int iA = iArrG[i];
            int i3 = 0;
            while (true) {
                int i4 = i2 - 1;
                if (i2 <= 0) {
                    break;
                }
                int i5 = (-1638454863) + i3;
                int i6 = (i5 >>> 2) & 3;
                int iA2 = iA;
                int i7 = 0;
                while (i7 < i) {
                    int i8 = i7 + 1;
                    iA2 = iArrG[i7] + a(i5, iArrG[i8], iA2, i7, i6, iArrG2);
                    iArrG[i7] = iA2;
                    i7 = i8;
                }
                i3 = i5;
                iA = a(i3, iArrG[0], iA2, i7, i6, iArrG2) + iArrG[i];
                iArrG[i] = iA;
                i2 = i4;
            }
        }
        return f(iArrG, false);
    }

    public static final String e(String str, String str2) {
        byte[] bArrD;
        String str3;
        try {
            bArrD = d(str.getBytes("UTF-8"), str2.getBytes("UTF-8"));
        } catch (UnsupportedEncodingException unused) {
            bArrD = null;
        }
        if (bArrD == null) {
            return null;
        }
        char[] cArr = {'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '+', '/'};
        StringBuilder sb = new StringBuilder();
        int length = bArrD.length % 3;
        int length2 = bArrD.length - length;
        int i = 0;
        while (i < length2) {
            int i2 = i + 2;
            int i3 = ((bArrD[i + 1] & 255) << 8) | ((bArrD[i] & 255) << 16);
            i += 3;
            int i4 = i3 | (bArrD[i2] & 255);
            sb.append(cArr[i4 >> 18]);
            sb.append(cArr[(i4 >> 12) & 63]);
            sb.append(cArr[(i4 >> 6) & 63]);
            sb.append(cArr[i4 & 63]);
        }
        if (length != 1) {
            if (length == 2) {
                int i5 = (bArrD[1 + i] & 255) | ((bArrD[i] & 255) << 8);
                sb.append(cArr[i5 >> 10]);
                sb.append(cArr[(i5 >> 4) & 63]);
                sb.append(cArr[(i5 & 15) << 2]);
                str3 = "=";
            }
            return sb.toString();
        }
        byte b = bArrD[i];
        sb.append(cArr[(b & 255) >> 2]);
        sb.append(cArr[(b & 3) << 4]);
        str3 = "==";
        sb.append(str3);
        return sb.toString();
    }

    public static byte[] f(int[] iArr, boolean z) {
        int length = iArr.length << 2;
        if (z) {
            int i = iArr[iArr.length - 1];
            int i2 = length - 4;
            if (i < length - 7 || i > i2) {
                return null;
            }
            length = i;
        }
        byte[] bArr = new byte[length];
        for (int i3 = 0; i3 < length; i3++) {
            bArr[i3] = (byte) (iArr[i3 >>> 2] >>> ((i3 & 3) << 3));
        }
        return bArr;
    }

    public static int[] g(byte[] bArr, boolean z) {
        int[] iArr;
        int length = (bArr.length & 3) == 0 ? bArr.length >>> 2 : (bArr.length >>> 2) + 1;
        if (z) {
            iArr = new int[length + 1];
            iArr[length] = bArr.length;
        } else {
            iArr = new int[length];
        }
        int length2 = bArr.length;
        for (int i = 0; i < length2; i++) {
            int i2 = i >>> 2;
            iArr[i2] = iArr[i2] | ((bArr[i] & 255) << ((i & 3) << 3));
        }
        return iArr;
    }
}
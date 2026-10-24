// APK-derived crypto methods; Android Base64 adapter only. Synthetic fixtures in Git.
import java.nio.charset.*;import java.nio.*;import java.security.*;import javax.crypto.*;import javax.crypto.spec.*;import java.io.*;
class TunneltweakOracle {
 private static final String ENCRYPTION_KEY="TunnelTweak2024!", PBE_PREFIX="TTPBE1:";
 public static void main(String[] args) throws Exception {
  BufferedReader r=new BufferedReader(new InputStreamReader(System.in,StandardCharsets.UTF_8));String line;
  while((line=r.readLine())!=null){String[] p=line.split("\t",-1);String x=new String(java.util.Base64.getDecoder().decode(p[1]),StandardCharsets.UTF_8);String password=p.length>2?new String(java.util.Base64.getDecoder().decode(p[2]),StandardCharsets.UTF_8):"test-only ñ🐺";String v;
   switch(p[0]) {
    case "file-cbc-encrypt":v=encryptAES(x);break;
    case "file-cbc":v=decryptAES(x);break;
    case "file-pbe-encrypt":v=encryptWithPassphrase(x,password);break;
    case "file-pbe":v=decryptWithPassphrase(x,password);break;
    case "file-xor-encrypt":byte[] a=x.getBytes(StandardCharsets.UTF_8);for(int i=0;i<a.length;i++)a[i]^=90;v=Base64.encodeToString(a,2);break;
    case "file-xor":v=decodeConfigLegacy(x);break;
    case "catalog-encrypt":v=SecureConfigEncryption.encrypt(x);break;
    case "catalog":v=SecureConfigEncryption.decrypt(x);break;
    case "catalog-keyed-encrypt":v=SecureConfigEncryption.encrypt(x,password);break;
    case "catalog-keyed":v=SecureConfigEncryption.decrypt(x,password);break;
    case "catalog-legacy":v=SecureConfigEncryption.decodeLegacy(x);break;
    default:throw new IllegalArgumentException("command");
   }
   if(v==null)throw new IllegalArgumentException("invalid sample");
   System.out.println(java.util.Base64.getEncoder().encodeToString(v.getBytes(StandardCharsets.UTF_8)));
  }
 }
    private static String decodeConfigLegacy(String str) {
        try {
            byte[] bArrDecode = Base64.decode(str, 2);
            byte[] bArr = new byte[bArrDecode.length];
            for (int i = 0; i < bArrDecode.length; i++) {
                bArr[i] = (byte) (bArrDecode[i] ^ 90);
            }
            return new String(bArr, StandardCharsets.UTF_8);
        } catch (Exception unused) {
            return null;
        }
    }
    private static String decryptAES(String str) {
        try {
            byte[] bArrDecode = Base64.decode(str, 2);
            if (bArrDecode.length < 16) {
                return null;
            }
            byte[] bArr = new byte[16];
            System.arraycopy(bArrDecode, 0, bArr, 0, 16);
            IvParameterSpec ivParameterSpec = new IvParameterSpec(bArr);
            int length = bArrDecode.length - 16;
            byte[] bArr2 = new byte[length];
            System.arraycopy(bArrDecode, 16, bArr2, 0, length);
            Charset charset = StandardCharsets.UTF_8;
            SecretKeySpec secretKeySpec = new SecretKeySpec(ENCRYPTION_KEY.getBytes(charset), "AES");
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(2, secretKeySpec, ivParameterSpec);
            return new String(cipher.doFinal(bArr2), charset);
        } catch (Exception unused) {
            return null;
        }
    }
    private static String decryptWithPassphrase(String str, String str2) {
        try {
            byte[] bArrDecode = Base64.decode(str.substring(7), 2);
            if (bArrDecode.length < 44) {
                return null;
            }
            byte[] bArr = new byte[16];
            byte[] bArr2 = new byte[12];
            System.arraycopy(bArrDecode, 0, bArr, 0, 16);
            System.arraycopy(bArrDecode, 16, bArr2, 0, 12);
            int length = bArrDecode.length - 28;
            byte[] bArr3 = new byte[length];
            System.arraycopy(bArrDecode, 28, bArr3, 0, length);
            SecretKeySpec secretKeySpecDeriveKey = deriveKey(str2, bArr);
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(2, secretKeySpecDeriveKey, new GCMParameterSpec(128, bArr2));
            return new String(cipher.doFinal(bArr3), StandardCharsets.UTF_8);
        } catch (Exception unused) {
            return null;
        }
    }
    private static SecretKeySpec deriveKey(String str, byte[] bArr) throws Exception {
        PBEKeySpec pBEKeySpec = new PBEKeySpec(str.toCharArray(), bArr, 120000, 256);
        byte[] encoded = SecretKeyFactory.getInstance("PBKDF2withHmacSHA256").generateSecret(pBEKeySpec).getEncoded();
        pBEKeySpec.clearPassword();
        return new SecretKeySpec(encoded, "AES");
    }
    private static String encryptAES(String str) {
        try {
            Charset charset = StandardCharsets.UTF_8;
            SecretKeySpec secretKeySpec = new SecretKeySpec(ENCRYPTION_KEY.getBytes(charset), "AES");
            byte[] bArr = new byte[16];
            new SecureRandom().nextBytes(bArr);
            IvParameterSpec ivParameterSpec = new IvParameterSpec(bArr);
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(1, secretKeySpec, ivParameterSpec);
            byte[] bArrDoFinal = cipher.doFinal(str.getBytes(charset));
            byte[] bArr2 = new byte[bArrDoFinal.length + 16];
            System.arraycopy(bArr, 0, bArr2, 0, 16);
            System.arraycopy(bArrDoFinal, 0, bArr2, 16, bArrDoFinal.length);
            return Base64.encodeToString(bArr2, 2);
        } catch (Exception unused) {
            return null;
        }
    }
    private static String encryptWithPassphrase(String str, String str2) {
        try {
            byte[] bArr = new byte[16];
            byte[] bArr2 = new byte[12];
            SecureRandom secureRandom = new SecureRandom();
            secureRandom.nextBytes(bArr);
            secureRandom.nextBytes(bArr2);
            SecretKeySpec secretKeySpecDeriveKey = deriveKey(str2, bArr);
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(1, secretKeySpecDeriveKey, new GCMParameterSpec(128, bArr2));
            byte[] bArrDoFinal = cipher.doFinal(str.getBytes(StandardCharsets.UTF_8));
            byte[] bArr3 = new byte[bArrDoFinal.length + 28];
            System.arraycopy(bArr, 0, bArr3, 0, 16);
            System.arraycopy(bArr2, 0, bArr3, 16, 12);
            System.arraycopy(bArrDoFinal, 0, bArr3, 28, bArrDoFinal.length);
            return PBE_PREFIX + Base64.encodeToString(bArr3, 2);
        } catch (Exception unused) {
            return null;
        }
    }
}


/* JADX INFO: loaded from: classes.dex */
class SecureConfigEncryption {
    private static final String CIPHER_ALGORITHM = "AES/GCM/NoPadding";
    private static final int GCM_TAG_LENGTH = 128;
    private static final int ITERATIONS = 10000;
    private static final int IV_LENGTH = 12;
    private static final String KEY_ALGORITHM = "PBKDF2WithHmacSHA256";
    private static final int KEY_LENGTH = 256;
    private static final String PASSPHRASE = "TunnelTweak-Secure-v1";
    private static final int SALT_LENGTH = 16;
    private static final String TAG = "SecureConfigEncryption";

    public static String decodeLegacy(String str) {
        try {
            String str2 = new String(Base64.decode(str, 0), StandardCharsets.UTF_8);
            if (str2.trim().startsWith("{")) {
                return str2;
            }
            return null;
        } catch (Exception unused) {
            return null;
        }
    }

    public static String decrypt(String str) {
        return decrypt(str, PASSPHRASE);
    }

    private static SecretKey deriveKey(String str, byte[] bArr) throws Exception {
        PBEKeySpec pBEKeySpec = new PBEKeySpec(str.toCharArray(), bArr, 10000, 256);
        byte[] encoded = SecretKeyFactory.getInstance(KEY_ALGORITHM).generateSecret(pBEKeySpec).getEncoded();
        pBEKeySpec.clearPassword();
        return new SecretKeySpec(encoded, "AES");
    }

    public static String encrypt(String str) {
        return encrypt(str, PASSPHRASE);
    }

    public static boolean isEncrypted(String str) {
        if (str == null || str.isEmpty()) {
            return false;
        }
        try {
            return Base64.decode(str, 2).length >= 44;
        } catch (Exception unused) {
            return false;
        }
    }

    public static String decrypt(String str, String str2) {
        try {
            byte[] bArrDecode = Base64.decode(str, 2);
            if (bArrDecode.length < 44) {
                return null;
            }
            ByteBuffer byteBufferWrap = ByteBuffer.wrap(bArrDecode);
            byte[] bArr = new byte[16];
            byte[] bArr2 = new byte[12];
            byte[] bArr3 = new byte[bArrDecode.length - 28];
            byteBufferWrap.get(bArr);
            byteBufferWrap.get(bArr2);
            byteBufferWrap.get(bArr3);
            SecretKey secretKeyDeriveKey = deriveKey(str2, bArr);
            Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
            cipher.init(2, secretKeyDeriveKey, new GCMParameterSpec(128, bArr2));
            return new String(cipher.doFinal(bArr3), StandardCharsets.UTF_8);
        } catch (Exception unused) {
            return null;
        }
    }

    public static String encrypt(String str, String str2) {
        try {
            byte[] bytes = str.getBytes(StandardCharsets.UTF_8);
            SecureRandom secureRandom = new SecureRandom();
            byte[] bArr = new byte[16];
            byte[] bArr2 = new byte[12];
            secureRandom.nextBytes(bArr);
            secureRandom.nextBytes(bArr2);
            SecretKey secretKeyDeriveKey = deriveKey(str2, bArr);
            Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
            cipher.init(1, secretKeyDeriveKey, new GCMParameterSpec(128, bArr2));
            byte[] bArrDoFinal = cipher.doFinal(bytes);
            ByteBuffer byteBufferAllocate = ByteBuffer.allocate(bArrDoFinal.length + 28);
            byteBufferAllocate.put(bArr);
            byteBufferAllocate.put(bArr2);
            byteBufferAllocate.put(bArrDoFinal);
            return Base64.encodeToString(byteBufferAllocate.array(), 2);
        } catch (Exception unused) {
            return null;
        }
    }
}

class Base64 {
 static byte[] decode(String text,int flags){return java.util.Base64.getDecoder().decode(text.replaceAll("\\s", ""));}
 static String encodeToString(byte[] data,int flags){return java.util.Base64.getEncoder().encodeToString(data);}
}

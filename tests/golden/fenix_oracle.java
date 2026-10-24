import java.nio.*;import java.nio.charset.*;import java.security.*;import java.util.*;import java.io.*;import javax.crypto.*;import javax.crypto.spec.*;
class FenixOracle {
 static final String CATALOG_PASSWORD="🔥🔥🔥vpnfenix⭐️⭐️⭐️";
 static final String FIELD_PASSWORD="FenxM22_07!89Dev";
 static byte[] b64(String s){return Base64.getDecoder().decode(s);}
 static String enc(byte[] b){return Base64.getEncoder().encodeToString(b);}
 static byte[] ascii(String s){return s.getBytes(StandardCharsets.UTF_8);}
    public static String outer(String str, String str2) throws Exception {
        ByteBuffer byteBufferWrap = ByteBuffer.wrap(Base64.getDecoder().decode(str2));
        byte[] bArr = new byte[8];
        byteBufferWrap.get(bArr);
        if (!Arrays.equals(bArr, "WakkoDev".getBytes(StandardCharsets.US_ASCII))) {
            throw new IllegalArgumentException("Encabezado inválido");
        }
        byte[] bArr2 = new byte[8];
        byteBufferWrap.get(bArr2);
        Charset charset = StandardCharsets.UTF_8;
        byte[] bArrderive = derive(str.getBytes(charset), bArr2, 32, 16);
        byte[] bArrCopyOfRange = Arrays.copyOfRange(bArrderive, 0, 32);
        byte[] bArrCopyOfRange2 = Arrays.copyOfRange(bArrderive, 32, 48);
        byte[] bArr3 = new byte[byteBufferWrap.remaining()];
        byteBufferWrap.get(bArr3);
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(2, new SecretKeySpec(bArrCopyOfRange, "AES"), new IvParameterSpec(bArrCopyOfRange2));
        return new String(cipher.doFinal(bArr3), charset);
    }

    public static byte[] derive(byte[] bArr, byte[] bArr2, int i, int i2) throws NoSuchAlgorithmException {
        MessageDigest messageDigest = MessageDigest.getInstance("MD5");
        int i3 = i + i2;
        byte[] bArr3 = new byte[i3];
        byte[] bArrDigest = new byte[0];
        int i4 = 0;
        while (i4 < i3) {
            messageDigest.update(bArrDigest);
            messageDigest.update(bArr);
            messageDigest.update(bArr2);
            bArrDigest = messageDigest.digest();
            int iMin = Math.min(bArrDigest.length, i3 - i4);
            System.arraycopy(bArrDigest, 0, bArr3, i4, iMin);
            i4 += iMin;
        }
        return bArr3;
    }
    public static String rotate(String str, int i) {
        StringBuilder sb = new StringBuilder();
        for (int i2 = 0; i2 < str.length(); i2++) {
            char cCharAt = str.charAt(i2);
            if (!Character.isLetter(cCharAt)) {
                sb.append(cCharAt);
            } else if (Character.isUpperCase(cCharAt)) {
                sb.append((char) ((((cCharAt + i) - 65) % 26) + 65));
            } else {
                sb.append((char) ((((cCharAt + i) - 97) % 26) + 97));
            }
        }
        return sb.toString();
    }


 static String field(String s) throws Exception {
  byte[] raw=Base64.getUrlDecoder().decode(s);byte[] key=Arrays.copyOf(ascii(FIELD_PASSWORD),32);
  Cipher c=Cipher.getInstance("AES/CBC/PKCS5Padding");c.init(2,new SecretKeySpec(key,"AES"),new IvParameterSpec(Arrays.copyOf(raw,16)));
  return rotate(new String(c.doFinal(Arrays.copyOfRange(raw,16,raw.length)),StandardCharsets.UTF_8),21);
 }
 static String fieldEncrypt(String s) throws Exception {
  byte[] iv=new byte[16];for(int i=0;i<16;i++)iv[i]=(byte)(i+17);
  Cipher c=Cipher.getInstance("AES/CBC/PKCS5Padding");c.init(1,new SecretKeySpec(Arrays.copyOf(ascii(FIELD_PASSWORD),32),"AES"),new IvParameterSpec(iv));
  byte[] raw=c.doFinal(ascii(rotate(s,5)));ByteArrayOutputStream out=new ByteArrayOutputStream();out.write(iv);out.write(raw);return Base64.getUrlEncoder().withoutPadding().encodeToString(out.toByteArray());
 }
 static byte[] profileKey(byte[] salt) throws Exception {return SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256").generateSecret(new PBEKeySpec("fubvx788b46v".toCharArray(),salt,1000,128)).getEncoded();}
 static String profileEncrypt(String xml) throws Exception {
  byte[] salt=new byte[32],nonce=new byte[12];for(int i=0;i<32;i++)salt[i]=(byte)(i+1);for(int i=0;i<12;i++)nonce[i]=(byte)(i+97);
  Cipher c=Cipher.getInstance("AES/GCM/NoPadding");c.init(1,new SecretKeySpec(profileKey(salt),"AES"),new GCMParameterSpec(128,nonce));
  return enc(salt)+"."+enc(nonce)+"."+enc(c.doFinal(ascii(xml)));
 }
 static String profileDecrypt(String text) throws Exception {
  String[] p=text.split("\\.");Cipher c=Cipher.getInstance("AES/GCM/NoPadding");c.init(2,new SecretKeySpec(profileKey(b64(p[0])),"AES"),new GCMParameterSpec(128,b64(p[1])));return new String(c.doFinal(b64(p[2])),StandardCharsets.UTF_8);
 }
 static byte[] des(byte[] b,int mode) throws Exception {Cipher c=Cipher.getInstance("DES/ECB/PKCS5Padding");c.init(mode,new SecretKeySpec(ascii("cinbdf66"),"DES"));return c.doFinal(b);}
 static String outerEncrypt(String text) throws Exception {
  byte[] salt=new byte[]{1,2,3,4,5,6,7,8};byte[] d=derive(ascii(CATALOG_PASSWORD),salt,32,16);
  Cipher c=Cipher.getInstance("AES/CBC/PKCS5Padding");c.init(1,new SecretKeySpec(Arrays.copyOfRange(d,0,32),"AES"),new IvParameterSpec(Arrays.copyOfRange(d,32,48)));
  ByteArrayOutputStream o=new ByteArrayOutputStream();o.write(ascii("WakkoDev"));o.write(salt);o.write(c.doFinal(ascii(text)));return enc(o.toByteArray());
 }
 public static void main(String[] a) throws Exception {
  BufferedReader r=new BufferedReader(new InputStreamReader(System.in,StandardCharsets.UTF_8));String line;
  while((line=r.readLine())!=null){String[] p=line.split("\t",-1);String s=new String(b64(p[1]),StandardCharsets.UTF_8);String v;
   switch(p[0]) {
    case "outer":v=outer(CATALOG_PASSWORD,s);break;
    case "outer-encrypt":v=outerEncrypt(s);break;
    case "field":v=field(s);break;
    case "field-encrypt":v=fieldEncrypt(s);break;
    case "rotate":v=rotate(s,21);break;
    case "profile-encrypt":v=profileEncrypt(s);break;
    case "profile-decrypt":v=profileDecrypt(s);break;
    case "des-encrypt":v=enc(des(ascii(s),1));break;
    case "des-decrypt":v=new String(des(b64(s),2),StandardCharsets.UTF_8);break;
    default:throw new IllegalArgumentException("command");
   }
   System.out.println(enc(ascii(v)));
  }
 }
}

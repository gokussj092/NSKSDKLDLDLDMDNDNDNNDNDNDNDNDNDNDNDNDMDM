import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.*;
import javax.crypto.*;
import javax.crypto.spec.*;

// Independent JCA transcription of build129 ur.g/ur.h, not Python code.
class CatalogOracle {
    static final String GLYPHS=new String(Base64.getDecoder().decode("4paZ4paa4pab4pac4pad4pae4paf4paD4paE4paF4paG4paH4paI4paJ4paK4paQ"),StandardCharsets.UTF_8);
    static final String ROT="0123456789ABCDEFGHJKLMNPQRSTUVWXYZ";
    static byte[] outerKey(byte[] pass)throws Exception {
        return MessageDigest.getInstance("SHA-256").digest(HexFormat.of().withUpperCase().formatHex(pass).getBytes(StandardCharsets.US_ASCII));
    }
    static byte[] outer(byte[] input,byte[] pass,boolean enc)throws Exception {
        Cipher cipher=Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(enc?Cipher.ENCRYPT_MODE:Cipher.DECRYPT_MODE,new SecretKeySpec(outerKey(pass),"AES"),new IvParameterSpec(new byte[16]));
        if(enc) {
            byte[] token=Base64.getEncoder().encode(cipher.doFinal(input));StringBuilder result=new StringBuilder();
            for(byte b:token){result.append(GLYPHS.charAt((b&255)>>>4));result.append(GLYPHS.charAt(b&15));}
            return result.toString().getBytes(StandardCharsets.UTF_8);
        }
        String text=new String(input,StandardCharsets.UTF_8).strip();
        if(text.length()%2!=0)throw new IllegalArgumentException("glyph length");
        byte[] raw=new byte[text.length()/2];
        for(int i=0;i<raw.length;i++){
            int hi=GLYPHS.indexOf(text.charAt(i*2)),lo=GLYPHS.indexOf(text.charAt(i*2+1));
            if(hi<0||lo<0)throw new IllegalArgumentException("glyph");raw[i]=(byte)(hi*16+lo);
        }
        return cipher.doFinal(Base64.getDecoder().decode(raw));
    }
    static String rotate(String input,int shift) {
        StringBuilder result=new StringBuilder();
        for(char c:input.toCharArray()){int at=ROT.indexOf(c);result.append(at<0?c:ROT.charAt((at+shift)%ROT.length()));}
        return result.toString();
    }
    static byte[] field(byte[] input,byte[] key,boolean enc)throws Exception {
        Cipher cipher=Cipher.getInstance("AES/GCM/NoPadding");
        if(enc) { // Fictional deterministic fixtures only, not a production exporter.
            byte[] nonce=Arrays.copyOf(MessageDigest.getInstance("SHA-256").digest(input),12);
            String shifted=rotate(new String(input,StandardCharsets.UTF_8),1);
            cipher.init(Cipher.ENCRYPT_MODE,new SecretKeySpec(key,"AES"),new GCMParameterSpec(128,nonce));
            byte[] sealed=cipher.doFinal(Base64.getEncoder().encode(shifted.getBytes(StandardCharsets.UTF_8)));
            byte[] result=Arrays.copyOf(nonce,nonce.length+sealed.length);System.arraycopy(sealed,0,result,12,sealed.length);
            return Base64.getEncoder().encode(result);
        }
        byte[] raw=Base64.getMimeDecoder().decode(input);
        if(raw.length<28)throw new IllegalArgumentException("GCM length");
        cipher.init(Cipher.DECRYPT_MODE,new SecretKeySpec(key,"AES"),new GCMParameterSpec(128,raw,0,12));
        byte[] clear=Base64.getDecoder().decode(cipher.doFinal(raw,12,raw.length-12));
        return rotate(new String(clear,StandardCharsets.UTF_8),33).getBytes(StandardCharsets.UTF_8);
    }
    public static void main(String[]args)throws Exception {
        var reader=new BufferedReader(new InputStreamReader(System.in,StandardCharsets.UTF_8));String line;
        while((line=reader.readLine())!=null){String[] f=line.split("\t",-1);byte[] key=Base64.getDecoder().decode(f[1]),data=Base64.getDecoder().decode(f[2]);
            byte[] result=switch(f[0]){case "O"->outer(data,key,false);case "E"->outer(data,key,true);case "F"->field(data,key,false);case "G"->field(data,key,true);default->throw new IllegalArgumentException("mode");};
            System.out.println(Base64.getEncoder().encodeToString(result));}
    }
}

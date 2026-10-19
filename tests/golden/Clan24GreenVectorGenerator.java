// Synthetic reference vectors: JCE OpenSSL-compatible CBC and APK XXTEA variant.
// Java int overflow and unsigned shifts reproduce k8.l.a/p/X/Y.
// Run: java tests/golden/Clan24GreenVectorGenerator.java
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

class Clan24GreenVectorGenerator {
    static String quote(String s) {
        StringBuilder b=new StringBuilder("\"");
        for(char c:s.toCharArray()) {
            switch(c) {
                case '"':b.append("\\\"");break;
                case '\\':b.append("\\\\");break;
                case '\r':b.append("\\r");break;
                case '\n':b.append("\\n");break;
                case '\t':b.append("\\t");break;
                default:if(c<32)b.append(String.format("\\u%04x",(int)c));else b.append(c);
            }
        }
        return b.append('"').toString();
    }
    static int mx(int sum,int y,int z,int position,int e,int[] key) {
        return ((sum^y)+(key[(position&3)^e]^z))^(((z>>>5)^(y<<2))+((y>>>3)^(z<<4)));
    }
    static String profile(String text) {
        byte[] plain=text.getBytes(StandardCharsets.UTF_8);
        int[] words=new int[(plain.length+3)/4+1];
        for(int i=0;i<plain.length;i++)words[i>>>2]|=(plain[i]&255)<<((i&3)<<3);
        words[words.length-1]=plain.length;
        byte[] keyBytes=new byte[16],original="technore_008515".getBytes(StandardCharsets.UTF_8);
        System.arraycopy(original,0,keyBytes,0,Math.min(16,original.length));
        int[] key=new int[4];ByteBuffer.wrap(keyBytes).order(ByteOrder.LITTLE_ENDIAN).asIntBuffer().get(key);
        int last=words.length-1,z=words[last],sum=0;
        for(int round=6+52/words.length;round>0;round--) {
            sum-=1704280;int e=(sum>>>2)&3;
            for(int position=0;position<last;position++) {
                words[position]+=mx(sum,words[position+1],z,position,e,key);z=words[position];
            }
            words[last]+=mx(sum,words[0],z,last,e,key);z=words[last];
        }
        ByteBuffer out=ByteBuffer.allocate(words.length*4).order(ByteOrder.LITTLE_ENDIAN);
        for(int word:words)out.putInt(word);
        return Base64.getEncoder().encodeToString(out.array());
    }
    static String catalog(String text) throws Exception {
        byte[] salt={1,2,3,4,5,6,7,8},material=new byte[48],previous=new byte[0];
        MessageDigest digest=MessageDigest.getInstance("MD5");int at=0;
        while(at<material.length) {
            digest.update(previous);digest.update("mtscrypt".getBytes(StandardCharsets.US_ASCII));digest.update(salt);
            previous=digest.digest();System.arraycopy(previous,0,material,at,16);at+=16;
        }
        Cipher cipher=Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE,new SecretKeySpec(material,0,32,"AES"),new IvParameterSpec(material,32,16));
        byte[] encrypted=cipher.doFinal(text.getBytes(StandardCharsets.UTF_8));
        ByteBuffer out=ByteBuffer.allocate(16+encrypted.length);
        out.put("Salted__".getBytes(StandardCharsets.US_ASCII));out.put(salt);out.put(encrypted);
        return Base64.getEncoder().encodeToString(out.array());
    }
    public static void main(String[] args) throws Exception {
        String server="{\"Name\":\"Synthetic server\",\"SSHHost\":\"example.invalid\",\"SSHPort\":\"22\",\"Username\":\"synthetic\",\"Password\":\"fixture-only\",\"future\":null}";
        String payload="GET / HTTP/1.1\r\nHost: example.invalid\r\n\r\n";
        String base="\"Name\":\"Prueba 日本 Perú\",\"Direct\":false,\"Payload\":"+quote(payload)+",\"Server\":"+quote(server)+",\"HWID\":\"SYNTHETIC-DEVICE\",\"ExpireDate\":1,\"MobileData\":true,\"BlockRoot\":true,\"isPremium\":true,\"Note\":\"First\\nSecond\\r\\nThird\",\"future\":{\"values\":[null,false,\"\"]}";
        String expected="{"+base+"}";
        String catalog="{\"Version\":\"synthetic-1\",\"Message\":\"Fixture only\",\"Servers\":["+server+"],\"PremiumServers\":["+server+"],\"Tweaks\":["+expected+"],\"PremiumTweaks\":[],\"future\":{\"keep\":true}}";
        StringBuilder vectors=new StringBuilder();
        for(int i=0;i<4;i++) {
            String text="{"+base+",\"padding\":"+quote("x".repeat(i))+"}";
            if(i>0)vectors.append(',');
            vectors.append("{\"data\":").append(quote(profile(text))).append(",\"expected\":").append(text).append(",\"utf8Bytes\":").append(text.getBytes(StandardCharsets.UTF_8).length).append('}');
        }
        String[] invalid={"{\"a\":1,\"a\":2}","{\"a\":NaN}","{\"a\":1e999}","{\"a\":\"\\ud800\"}","[]","{broken}"};
        StringBuilder bad=new StringBuilder();
        for(int i=0;i<invalid.length;i++){if(i>0)bad.append(',');bad.append(quote(profile(invalid[i])));}
        String[] shortTexts={"{}","{\"a\":1}","{\"a\":12}","{\"a\":\"日\"}"};
        StringBuilder shortVectors=new StringBuilder();
        for(int i=0;i<shortTexts.length;i++) {
            if(i>0)shortVectors.append(',');
            shortVectors.append("{\"data\":").append(quote(profile(shortTexts[i]))).append(",\"expected\":").append(shortTexts[i]).append('}');
        }
        System.out.println("{\"source\":\"Synthetic OpenJDK/JCE and APK modified XXTEA; no real server data\",\"profile\":"+quote(profile(expected))+",\"expectedProfile\":"+expected+",\"catalog\":"+quote(catalog(catalog))+",\"expectedCatalog\":"+catalog+",\"lengthVectors\":["+vectors+"],\"shortVectors\":["+shortVectors+"],\"invalidProfiles\":["+bad+"]}");
    }
}

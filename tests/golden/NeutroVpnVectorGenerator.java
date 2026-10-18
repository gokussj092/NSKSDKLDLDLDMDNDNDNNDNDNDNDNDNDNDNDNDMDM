// Synthetic JCE vectors. Signing scalar 1 is PUBLIC TEST DATA, never an app key.
// Run: java tests/golden/NeutroVpnVectorGenerator.java
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.*;
import java.util.Base64;
import javax.crypto.*;
import javax.crypto.spec.*;

class NeutroVpnVectorGenerator {
    static final byte[] KEY = Base64.getDecoder().decode("3NyRmmrnhIr23hMCPDGJriYyGBUEAjGoPFX8PwU8qsY=");
    static final String PASSWORD = "  clave ñ 日本 \uD834\uDD1E  ";
    static String quote(String s) {
        StringBuilder b = new StringBuilder("\"");
        for (char c:s.toCharArray()) {
            switch(c) {
                case '"': b.append("\\\""); break;
                case '\\': b.append("\\\\"); break;
                case '\r': b.append("\\r"); break;
                case '\n': b.append("\\n"); break;
                case '\t': b.append("\\t"); break;
                default: if(c<32)b.append(String.format("\\u%04x",(int)c)); else b.append(c);
            }
        }
        return b.append('"').toString();
    }
    static byte[] sequence(int size,int start) {
        byte[] out=new byte[size];for(int i=0;i<size;i++)out[i]=(byte)(i+start);return out;
    }
    static String b64(byte[] b) {return Base64.getEncoder().encodeToString(b);}
    static byte[] encrypt(String text,byte[] key,byte[] nonce) throws Exception {
        Cipher c=Cipher.getInstance("AES/GCM/NoPadding");
        c.init(Cipher.ENCRYPT_MODE,new SecretKeySpec(key,"AES"),new GCMParameterSpec(128,nonce));
        return c.doFinal(text.getBytes(StandardCharsets.UTF_8));
    }
    static String profile(String text,boolean protectedFile) throws Exception {
        byte[] salt=protectedFile?sequence(16,32):new byte[0];
        byte[] nonce=sequence(12,protectedFile?80:64),key=KEY;
        if(protectedFile)key=SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")
            .generateSecret(new PBEKeySpec(PASSWORD.toCharArray(),salt,120000,256)).getEncoded();
        return "NVPNC1."+(protectedFile?"P":"L")+"."+b64(salt)+"."+b64(nonce)+"."+b64(encrypt(text,key,nonce));
    }
    static String catalog(String text,PrivateKey privateKey) throws Exception {
        byte[] nonce=sequence(12,96),encrypted=encrypt(text,KEY,nonce);
        SecureRandom rng=SecureRandom.getInstance("SHA1PRNG");rng.setSeed("neutro-synthetic-reference".getBytes(StandardCharsets.UTF_8));
        Signature signer=Signature.getInstance("SHA256withECDSA");signer.initSign(privateKey,rng);
        signer.update(nonce);signer.update(encrypted);
        return b64(nonce)+"."+b64(encrypted)+"."+b64(signer.sign());
    }
    public static void main(String[] args) throws Exception {
        AlgorithmParameters ap=AlgorithmParameters.getInstance("EC");ap.init(new ECGenParameterSpec("secp256r1"));
        ECParameterSpec spec=ap.getParameterSpec(ECParameterSpec.class);
        KeyFactory factory=KeyFactory.getInstance("EC");
        PrivateKey privateKey=factory.generatePrivate(new ECPrivateKeySpec(BigInteger.ONE,spec));
        PublicKey publicKey=factory.generatePublic(new ECPublicKeySpec(spec.getGenerator(),spec));
        String xray="{\"outbounds\":[{\"protocol\":\"vless\",\"future\":true}]}";
        String payload="GET / HTTP/1.1\r\nHost: example.invalid\r\n\r\n";
        String profile="{\"v\":2,\"name\":\"Sintético 日本\",\"mode\":6,\"host\":\"example.invalid\",\"port\":\"443\",\"user\":\"synthetic-user\",\"pass\":\"fixture-only\",\"proxyHost\":\"\",\"proxyPort\":\"80\",\"customPayload\":true,\"payload\":"+quote(payload)+",\"sni\":\"example.invalid\",\"tlsVersion\":\"TLSv1.3\",\"dnsServer\":\"1.1.1.1\",\"nameserver\":\"ns.example.invalid\",\"pubkey\":\"fixture-public-data\",\"xray\":"+quote(xray)+",\"udp\":true,\"mobileOnly\":true,\"rootBlock\":true,\"expiresAt\":1,\"lockId\":\"ABCD-EF12-3456\",\"unlocked\":true,\"message\":\"Keep all fields\",\"future\":{\"unknown\":[null,false,\"\"]}}";
        String catalog="{\"v\":7,\"profiles\":["+profile+"],\"sshHost\":\"example.invalid\",\"capXray\":"+quote(xray)+",\"future\":{\"keep\":true}}";
        System.out.println("{\"source\":\"Synthetic OpenJDK/JCE; public test signing scalar 1\",\"password\":"+quote(PASSWORD)+",\"catalogPublicKey\":"+quote(b64(publicKey.getEncoded()))+",\"expectedProfile\":"+profile+",\"expectedCatalog\":"+catalog+",\"local\":"+quote(profile(profile,false))+",\"protected\":"+quote(profile(profile,true))+",\"catalog\":"+quote(catalog(catalog,privateKey))+"}");
    }
}

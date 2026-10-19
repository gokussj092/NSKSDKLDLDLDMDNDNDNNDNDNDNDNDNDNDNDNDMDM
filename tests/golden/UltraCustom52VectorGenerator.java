// Synthetic deterministic fixtures, NOT a production exporter (fixed GCM nonce).
// Run from repository root:
// java tests/golden/UltraCustom52VectorGenerator.java > tests/golden/ultra_custom_52_vectors.json
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.MessageDigest;
import java.util.*;
import java.util.zip.Deflater;
import javax.crypto.*;
import javax.crypto.spec.*;

class UltraCustom52VectorGenerator {
    static final String PASSWORD = "Contraseña-Perú-日本語-🔑";
    static final byte[] KEY = HexFormat.of().parseHex("a78840e92f734b36fb");
    static byte[] utf8(String s) { return s.getBytes(StandardCharsets.UTF_8); }
    static byte[] join(byte[]... parts) throws Exception {
        var b = new ByteArrayOutputStream(); for (byte[] p : parts) b.write(p); return b.toByteArray();
    }
    static String quote(String s) {
        var b = new StringBuilder("\"");
        for (char c : s.toCharArray()) {
            if (c == '"' || c == '\\') b.append('\\').append(c);
            else if (c < 32) b.append(String.format("\\u%04x", (int)c));
            else b.append(c);
        }
        return b.append('"').toString();
    }
    static String object(Properties p) {
        var values = new ArrayList<String>();
        for (String k : new TreeSet<>(p.stringPropertyNames())) values.add(quote(k)+":"+quote(p.getProperty(k)));
        return "{"+String.join(",", values)+"}";
    }
    static byte[] xml(Properties p, String comment) throws Exception {
        var b = new ByteArrayOutputStream(); p.storeToXML(b, comment, "UTF-8"); return b.toByteArray();
    }
    static byte[] compressed(byte[] data, String marker) throws Exception {
        Deflater z = new Deflater(9, true);
        try {
            z.setDictionary(Files.readAllBytes(Path.of("tests/golden/ultra_custom_52_dictionary.txt")));
            z.setInput(data); z.finish(); var b = new ByteArrayOutputStream(); b.write(utf8(marker));
            byte[] buf = new byte[4096]; while (!z.finished()) b.write(buf, 0, z.deflate(buf)); return b.toByteArray();
        } finally { z.end(); }
    }
    static byte[] protect(byte[] data) throws Exception {
        byte[] salt = new byte[16], nonce = new byte[12];
        for (int i=0;i<16;i++) salt[i]=(byte)i;
        for (int i=0;i<12;i++) nonce[i]=(byte)(i+16);
        byte[] header=join(utf8("UAP1"),salt,nonce);
        byte[] key=SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")
            .generateSecret(new PBEKeySpec(PASSWORD.toCharArray(),salt,210000,256)).getEncoded();
        Cipher cipher=Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE,new SecretKeySpec(key,"AES"),new GCMParameterSpec(128,nonce));
        cipher.updateAAD(header); return join(header,cipher.doFinal(data));
    }
    static byte[] mask(byte[] data) {
        int s=0x91ac3f12; for(byte b:KEY) s^=b&255;
        byte[] out=new byte[data.length];
        for(int i=0;i<data.length;i++) {
            s^=s<<13; s^=s>>>17; s^=s<<5;
            int value=(((data[i]&255)^(KEY[(i+(s&255))%KEY.length]&255))+s)&255;
            out[i]=(byte)((value>>>4)|(value<<4));
        }
        return out;
    }
    static byte[] bundle(byte[] a, byte[] b) throws Exception {
        Properties p=new Properties(); p.setProperty("file.bundleFormat","UA-BUNDLE-1");
        p.setProperty("file.profileCount","2"); p.setProperty("profile.0",new String(a,StandardCharsets.UTF_8));
        p.setProperty("profile.1",new String(b,StandardCharsets.UTF_8));
        return compressed(xml(p,"Paquete de perfiles Ultra Custom"),"UAB1");
    }
    public static void main(String[] args) throws Exception {
        Properties one=new Properties();
        one.setProperty("file.appVersionCode","52");one.setProperty("file.profileFormat","2");
        one.setProperty("file.profileName","SSH Perú 日本語");one.setProperty("file.proteger","0");
        one.setProperty("sshServer","vpn.example.invalid");one.setProperty("sshPort","443");
        one.setProperty("sshUser","demo");one.setProperty("sshPass","synthetic-only");
        one.setProperty("proxyPayload","GET / HTTP/1.1\r\nHost: example.invalid\r\n\r\n");
        one.setProperty("profileNote","<b>Nota & prueba</b>");one.setProperty("futureField","keep me");one.setProperty("empty","");
        Properties two=new Properties();two.putAll(one);
        two.setProperty("file.profileName","V2Ray protegido");two.setProperty("file.proteger","1");
        two.setProperty("blockHwid","1");two.setProperty("hwidstring","synthetic-device");two.setProperty("file.validade","1");
        two.setProperty("v2rayjson","{\"outbounds\":[{\"protocol\":\"vless\",\"settings\":{\"vnext\":[{\"address\":\"vpn.example.invalid\",\"port\":443}]}}],\"future\":true}");
        byte[] a=xml(one,"Archivo de Configuracion"), b=xml(two,"Archivo de Configuracion");
        Properties wrapper=new Properties();wrapper.setProperty("file.profilePasswordFormat","1");
        wrapper.setProperty("file.profileName",two.getProperty("file.profileName"));
        wrapper.setProperty("file.passwordPayload",Base64.getEncoder().encodeToString(protect(compressed(b,"EXA1"))));
        Map<String,byte[]> stages=new LinkedHashMap<>();
        stages.put("single-plain",a);stages.put("single-password",protect(b));
        stages.put("link-plain",compressed(a,"EXA1"));stages.put("link-password",protect(compressed(b,"EXA1")));
        stages.put("bundle-plain",bundle(a,b));stages.put("bundle-outer-password",protect(bundle(a,b)));
        stages.put("bundle-mixed-password",bundle(a,xml(wrapper,"Perfil protegido")));
        System.out.print("{\n  \"producer\":\"OpenJDK/JCE and raw DEFLATE; synthetic fixed nonce only\",\n  \"password\":"+quote(PASSWORD)+",\n  \"expectedProfiles\":["+object(one)+","+object(two)+"],\n  \"vectors\":[\n");
        int count=0;
        for(var e:stages.entrySet()) {
            byte[] stage=e.getValue(); String name=e.getKey();
            if(args.length>0) Files.write(Path.of(args[0],name+".stage"),stage);
            String sha=HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(stage));
            String expected=name.startsWith("bundle")?"[0,1]":name.endsWith("plain")?"[0]":"[1]";
            System.out.print("    {\"name\":"+quote(name)+",\"stageSha256\":"+quote(sha)+",\"expected\":"+expected+",\"data\":"+quote(Base64.getUrlEncoder().encodeToString(mask(stage)))+"}"+(++count<stages.size()?",":"")+"\n");
        }
        System.out.println("  ]\n}");
    }
}

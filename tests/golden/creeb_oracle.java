import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.*;
import javax.crypto.*;
import javax.crypto.spec.DESKeySpec;

// Independent JDK reference: original Dalvik shifts, DESKeySpec/Cipher("DES")
// and Properties.storeToXML/loadFromXML. Synthetic data only in --generate.
class CreebOracle {
    static String key() {
        int[] values={-98901911,1391026712,1087378526,1285886231,-985476289,-1358453613,166017041,969319060,1161095351,-834405800,-1176638128};
        int[] shifts={19,24,4,2,16,4,10,1,5,16,2};
        byte[] out=new byte[values.length];for(int i=0;i<out.length;i++)out[i]=(byte)(values[i]>>>shifts[i]);
        return new String(out,StandardCharsets.UTF_8);
    }
    static byte[] crypt(byte[] data,boolean encrypt)throws Exception {
        var k=SecretKeyFactory.getInstance("DES").generateSecret(new DESKeySpec(key().getBytes(StandardCharsets.UTF_8)));
        var c=Cipher.getInstance("DES");c.init(encrypt?Cipher.ENCRYPT_MODE:Cipher.DECRYPT_MODE,k);return c.doFinal(data);
    }
    static String quote(String s){
        StringBuilder o=new StringBuilder("\"");
        for(char c:s.toCharArray()){
            if(c=='"'||c=='\\')o.append('\\').append(c);
            else if(c<32)o.append(String.format("\\u%04x",(int)c));
            else o.append(c);
        }return o.append('"').toString();
    }
    static String json(Object v){
        if(v==null)return "null";if(v instanceof String)return quote((String)v);
        if(v instanceof Map){var a=new ArrayList<String>();for(var x:((Map<?,?>)v).entrySet())a.add(quote(x.getKey().toString())+":"+json(x.getValue()));return "{"+String.join(",",a)+"}";}
        if(v instanceof List){var a=new ArrayList<String>();for(var x:(List<?>)v)a.add(json(x));return "["+String.join(",",a)+"]";}
        return v.toString();
    }
    static Map<String,Object> opened(byte[] xml)throws Exception {
        var p=new Properties();p.loadFromXML(new ByteArrayInputStream(xml));
        var map=new TreeMap<String,String>();for(String k:p.stringPropertyNames())map.put(k,p.getProperty(k));
        return Map.of("xmlBase64",Base64.getEncoder().encodeToString(xml),"properties",map);
    }
    static void generate()throws Exception {
        var files=new ArrayList<Object>();
        for(boolean locked:new boolean[]{false,true}){
            var p=new Properties();
            p.setProperty("file.appVersionCode","3");p.setProperty("tunnelType","8");
            p.setProperty("file.proteger",locked?"1":"0");p.setProperty("file.pedirLogin",locked?"1":"0");
            p.setProperty("file.validade","0");p.setProperty("file.msg","Synthetic é 日本語 😀");
            p.setProperty("sshServer","example.invalid");p.setProperty("sshPort","443");
            p.setProperty("sshUser","synthetic-user");p.setProperty("sshPass","synthetic-connection-password");
            p.setProperty("proxyPayload","GET / HTTP/1.1\r\nHost: [host]\r\n\r\n");
            p.setProperty("empty","");p.setProperty("unknown","<tag> & \"quotes\"\t");
            p.setProperty("v2rayjson","{\"outbounds\":[{\"protocol\":\"vless\"}],\"unknown\":null}");
            p.setProperty("blockHwid",locked?"1":"0");p.setProperty("hwidstring",locked?"synthetic-device":"");
            p.setProperty("file.blockedPackages","synthetic.package.one,synthetic.package.two");
            if(locked)p.setProperty("file.passwordHash",HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest("synthetic-pass".getBytes(StandardCharsets.UTF_8))));
            var stream=new ByteArrayOutputStream();p.storeToXML(stream,"Configuration File","UTF-8");byte[] xml=stream.toByteArray();
            var v=new LinkedHashMap<String,Object>(opened(xml));v.put("name",locked?"locked":"normal");
            v.put("cipherBase64",Base64.getEncoder().encodeToString(crypt(xml,true)));files.add(v);
        }
        byte[] duplicates=("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"+
            "<!DOCTYPE properties SYSTEM \"http://java.sun.com/dtd/properties.dtd\">\n"+
            "<properties><entry key=\"duplicate\">first</entry><entry key=\"duplicate\">last</entry>"+
            "<entry key=\"emoji\">&#32;&#xd83d;&#xde00; &#55357;&#56832;</entry><entry key=\"empty\"/>"+
            "<entry key=\"crlf\">one&#13;&#10;two</entry></properties>").getBytes(StandardCharsets.UTF_8);
        var duplicateCase=new LinkedHashMap<String,Object>(opened(duplicates));duplicateCase.put("name","duplicate-entries");
        duplicateCase.put("cipherBase64",Base64.getEncoder().encodeToString(crypt(duplicates,true)));files.add(duplicateCase);
        var profiles=new ArrayList<Object>();
        for(int i=0;i<2;i++){
            var prefs=new LinkedHashMap<String,Object>();prefs.put("sshServer","example.invalid");prefs.put("sshPass","synthetic");
            prefs.put("dnsForward",true);prefs.put("empty","");prefs.put("v2rayjson","{\"outbounds\":[]}");
            prefs.put("unknown",Arrays.asList(null,false,7,Map.of("Password","untouched")));
            var p=new LinkedHashMap<String,Object>();p.put("id","synthetic-"+i);p.put("name","Synthetic "+i);p.put("hostPort","example.invalid:443");
            p.put("tunnelType",i==0?1:8);p.put("prefs",prefs);p.put("isImported",false);p.put("isProtected",true);profiles.add(p);
        }
        var bundles=new ArrayList<Object>();
        for(boolean locked:new boolean[]{false,true}){
            var b=new LinkedHashMap<String,Object>();b.put("type","creeb_profile_bundle");b.put("version",1);b.put("profiles",profiles);
            if(locked)b.put("security",Map.of("requiresPassword",true,"passwordHash",
                HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest("synthetic-pass".getBytes(StandardCharsets.UTF_8))),
                "blockHwid",true,"hwidstring","synthetic-device"));
            b.put("message","Synthetic 😀\r\n");b.put("unknown",Arrays.asList(null,false,12));bundles.add(b);
        }
        System.out.println(json(Map.of("provenance","Independent JDK; synthetic only","desFiles",files,"jsonBundles",bundles)));
    }
    public static void main(String[] args)throws Exception {
        if(args.length==1 && args[0].equals("--generate")){generate();return;}
        var r=new BufferedReader(new InputStreamReader(System.in,StandardCharsets.UTF_8));String line;
        while((line=r.readLine())!=null){byte[] in=Base64.getDecoder().decode(line);
            if(args.length==1 && args[0].equals("--seal-xml"))System.out.println(Base64.getEncoder().encodeToString(crypt(in,true)));
            else System.out.println(json(opened(crypt(in,false))));
        }
    }
}

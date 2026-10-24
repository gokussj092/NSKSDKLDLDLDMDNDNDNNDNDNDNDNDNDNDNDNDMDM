import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.*;
import javax.crypto.*;
import javax.crypto.spec.*;

/** Independent JDK reference: Data streams, HmacSHA256 and AES/GCM/NoPadding.
 * No imports from the Python codec; only synthetic credentials in generated data.
 * Default: emit vectors. verify: read base64(envelope) TAB base64(UTF8 password).
 */
class oneftunnel_oracle {
 static final byte[] ROOT=HexFormat.of().parseHex("9e4f569a0a6cfd2da000b9de35ffe74a4e605c3eaecbdf477a13d709da233971");
 static final String[] TYPES={"SSH","VMESS","VLESS","TROJAN"};
 static Map<String,Object> map(Object... kv){var m=new LinkedHashMap<String,Object>();for(int i=0;i<kv.length;i+=2)m.put((String)kv[i],kv[i+1]);return m;}
 static byte[] ascii(String s){return s.getBytes(StandardCharsets.US_ASCII);}
 static byte[] cat(byte[]... arrays)throws Exception{var b=new ByteArrayOutputStream();for(byte[] a:arrays)b.write(a);return b.toByteArray();}
 static byte[] mac(byte[] key,byte[] data)throws Exception{Mac m=Mac.getInstance("HmacSHA256");m.init(new SecretKeySpec(key,"HmacSHA256"));return m.doFinal(data);}
 static byte[] key(int version,byte[] salt,byte[] aad,String password)throws Exception{
  String v=version==1?"v1":"v2";byte[] ikm=ROOT;
  if(!password.isEmpty())ikm=mac(ROOT,cat(ascii("1FT1 password "+v),password.getBytes(StandardCharsets.UTF_16BE)));
  return mac(mac(salt,ikm),cat(ascii("1FT1 HKDF AES-256-GCM "+v),aad,new byte[]{1}));
 }
 static void str(DataOutputStream d,String s)throws Exception{if(s==null){d.writeInt(-1);return;}byte[] b=s.getBytes(StandardCharsets.UTF_8);d.writeInt(b.length);d.write(b);}
 static String str(DataInputStream d,boolean shortLength)throws Exception{int n=shortLength?d.readUnsignedShort():d.readInt();if(n==-1)return null;if(n<0||n>2097152||n>d.available())throw new IOException("string");return new String(d.readNBytes(n),StandardCharsets.UTF_8);}
 static void shortStr(DataOutputStream d,String s)throws Exception{byte[] b=s.getBytes(StandardCharsets.UTF_8);d.writeShort(b.length);d.write(b);}
 static String choice(DataInputStream d,String... choices)throws Exception{return choices[d.readUnsignedByte()];}
 static Map<String,Object> config(byte[] raw)throws Exception{
  var d=new DataInputStream(new ByteArrayInputStream(raw));if(!Arrays.equals(d.readNBytes(4),ascii("CFG1")))throw new IOException("magic");int v=d.readUnsignedByte();
  var out=map("payloadVersion",v,"id",str(d,false),"name",str(d,false),"createdAt",d.readLong(),"message",str(d,false));
  int mask=v>=2?d.readInt():-1;out.put("fieldLockMask",mask==-1?null:mask);
  out.put("ssh",d.readBoolean()?map("host",str(d,false),"port",d.readInt(),"username",str(d,false),"password",str(d,false)):null);
  Map<String,Object> inject=null;
  if(d.readBoolean()){
   inject=map("mode",choice(d,"DIRECT","SSH_PAYLOAD","PROXY","PROXY_SNI","WILDCARD"),"payload",str(d,false),"proxyHost",str(d,false));
   int port=d.readInt();inject.put("proxyPort",port==-1?null:port);inject.put("sni",str(d,false));inject.put("wildcardHost",str(d,false));
  }out.put("inject",inject);
  out.put("dns",d.readBoolean()?map("primary",str(d,false),"secondary",str(d,false)):null);
  Map<String,Object> x=null;
  if(d.readBoolean()){
   x=map("protocol",choice(d,"VMESS","VLESS","TROJAN"),"host",str(d,false),"port",d.readInt(),"uuid",str(d,false),"password",str(d,false),"security",choice(d,"TLS","NONE","REALITY"),"network",choice(d,"WS","GRPC","RAW","XHTTP","HTTPUPGRADE"));
   for(String k:new String[]{"path","serviceName","sni","hostHeader","wildcardHost"})x.put(k,str(d,false));
   x.put("allowInsecure",v>=3?d.readBoolean():false);x.put("alpn",v>=3?str(d,false):null);
   for(String k:new String[]{"flow","fingerprint","realityPublicKey","shortId","spiderX"})x.put(k,v>=4?str(d,false):null);
   x.put("mode",v>=5?str(d,false):null);
  }out.put("xray",x);if(d.available()!=0)throw new IOException("trailing CFG1");return out;
 }
 static Map<String,Object> decode(byte[] raw,String password)throws Exception{
  var d=new DataInputStream(new ByteArrayInputStream(raw));if(!Arrays.equals(d.readNBytes(4),ascii("1FT1")))throw new IOException("magic");
  int v=d.readUnsignedByte();if(d.readUnsignedByte()!=1||d.readUnsignedByte()!=1||d.readUnsignedByte()!=0)throw new IOException("header");
  byte[] salt=d.readNBytes(16),nonce=d.readNBytes(12);int an=d.readInt(),cn=d.readInt();byte[] aad=d.readNBytes(an),cipher=d.readNBytes(cn);if(d.available()!=0||cipher.length!=cn)throw new IOException("size");
  var a=new DataInputStream(new ByteArrayInputStream(aad));int av=a.readUnsignedByte();if(av!=v)throw new IOException("version");
  var m=map("version",av,"package",str(a,true),"signatureSha256",str(a,true),"configVersion",Integer.toUnsignedLong(a.readInt()),"keySlot",0,"minimumAppBuild",null,"createdAt",null);
  if(av>=2){m.put("keySlot",a.readInt());m.put("minimumAppBuild",a.readLong());m.put("createdAt",a.readLong());}
  m.put("expiredAt",a.readLong());m.put("configType",choice(a,TYPES));int lock=a.readUnsignedByte();m.put("lockMode",lock);m.put("blockRoot",av>=3?a.readBoolean():false);
  if(a.available()!=0)throw new IOException("trailing AAD");
  Cipher c=Cipher.getInstance("AES/GCM/NoPadding");c.init(Cipher.DECRYPT_MODE,new SecretKeySpec(key(v,salt,aad,lock==2?password:""),"AES"),new GCMParameterSpec(128,nonce));c.updateAAD(aad);byte[] plain=c.doFinal(cipher);
  m.put("authenticated",true);m.put("algorithm","AES-256-GCM");m.put("kdf","HKDF-SHA256");
  return map("application","1FTunnel","format","1FT1","metadata",m,"config",config(plain),"isPartial",false);
 }
 static byte[] payload(int v,int seed,int type)throws Exception{
  var b=new ByteArrayOutputStream();var d=new DataOutputStream(b);d.write(ascii("CFG1"));d.writeByte(v);
  str(d,"synthetic-"+seed);str(d,"Perfil de prueba 😀\u0000"+seed);d.writeLong(1700000000000L);str(d,seed%2==0?null:"mensaje\nprueba");
  if(v>=2)d.writeInt(seed%2==0?-1:511);
  boolean ssh=type==0||seed%2==0;d.writeBoolean(ssh);if(ssh){str(d,"ssh.example.invalid");d.writeInt(22);str(d,"");str(d,"synthetic-password");}
  d.writeBoolean(seed%2==0);if(seed%2==0){d.writeByte(seed%5);str(d,"GET / HTTP/1.1\r\n\r\n");str(d,null);d.writeInt(-1);str(d,"");str(d,"*.example.invalid");}
  d.writeBoolean(seed%2==0);if(seed%2==0){str(d,"192.0.2.53");str(d,"");}
  boolean xray=type!=0||seed%2==0;d.writeBoolean(xray);if(xray){
   d.writeByte(type==0?seed%3:type-1);str(d,"xray.example.invalid");d.writeInt(443);str(d,"00000000-0000-0000-0000-000000000000");str(d,null);d.writeByte(seed%3);d.writeByte(seed%5);
   for(String s:new String[]{"/ws",null,"sni.example.invalid","",null})str(d,s);
   if(v>=3){d.writeBoolean(seed%2==0);str(d,"h2,http/1.1");}
   if(v>=4)for(String s:new String[]{"xtls-rprx-vision","chrome","synthetic-public-key","abcd",null})str(d,s);
   if(v>=5)str(d,"auto");
  }return b.toByteArray();
 }
 static byte[] envelope(int v,int pv,int seed,int type,int lock,String password)throws Exception{
  var a=new ByteArrayOutputStream();var d=new DataOutputStream(a);d.writeByte(v);shortStr(d,"com.oneftunnel.app");
  shortStr(d,seed%2==0?"d5d6665868244981a7ce3e9ea543610af83ed3b9c00322f0a7ffed88d327d589":"0c7718166c0b60cb09229dfc5f8c02f2567ea41fb75f7c7b792111c65dfaf937");d.writeInt(1);
  if(v>=2){d.writeInt(seed%2);d.writeLong(122);d.writeLong(1700000000000L);}d.writeLong(seed%2==0?-1:1800000000000L);d.writeByte(type);d.writeByte(lock);if(v>=3)d.writeBoolean(seed%2==0);
  byte[] aad=a.toByteArray(),salt=new byte[16],nonce=new byte[12];for(int i=0;i<16;i++)salt[i]=(byte)(i+seed);for(int i=0;i<12;i++)nonce[i]=(byte)(128+i+seed);
  Cipher c=Cipher.getInstance("AES/GCM/NoPadding");c.init(Cipher.ENCRYPT_MODE,new SecretKeySpec(key(v,salt,aad,password),"AES"),new GCMParameterSpec(128,nonce));c.updateAAD(aad);byte[] cipher=c.doFinal(payload(pv,seed,type));
  var b=new ByteArrayOutputStream();d=new DataOutputStream(b);d.write(ascii("1FT1"));d.write(new byte[]{(byte)v,1,1,0});d.write(salt);d.write(nonce);d.writeInt(aad.length);d.writeInt(cipher.length);d.write(aad);d.write(cipher);return b.toByteArray();
 }
 static String json(Object x){
  if(x==null)return "null";if(x instanceof Boolean||x instanceof Number)return x.toString();
  if(x instanceof Map<?,?> m){var j=new StringJoiner(",","{","}");m.forEach((k,v)->j.add(json(k)+":"+json(v)));return j.toString();}
  if(x instanceof List<?> l){var j=new StringJoiner(",","[","]");for(Object v:l)j.add(json(v));return j.toString();}
  var b=new StringBuilder("\"");for(char c:x.toString().toCharArray())switch(c){case '"'->b.append("\\\"");case '\\'->b.append("\\\\");default->{if(c<32)b.append(String.format("\\u%04x",(int)c));else b.append(c);}}return b.append('"').toString();
 }
 public static void main(String[] args)throws Exception{
  if(args.length>0&&args[0].equals("verify")){
   var reader=new BufferedReader(new InputStreamReader(System.in,StandardCharsets.UTF_8));String line;while((line=reader.readLine())!=null){var p=line.split("\t",-1);System.out.println(json(decode(Base64.getDecoder().decode(p[0]),p.length>1?new String(Base64.getDecoder().decode(p[1]),StandardCharsets.UTF_8):"")));}return;
  }
  var vectors=new ArrayList<Object>();int seed=0;
  for(int v=1;v<=3;v++)for(int pv=1;pv<=5;pv++){
   int n=seed++,type=n%4,lock=n%3;String pass=lock==2?"prueba-😀-contraseña":"";byte[] raw=envelope(v,pv,n,type,lock,pass);
   String wire="1FTnl."+Base64.getUrlEncoder().withoutPadding().encodeToString(Arrays.copyOfRange(raw,4,raw.length));
   vectors.add(map("label","v"+v+"-cfg"+pv,"wire",wire,"password",pass,"expected",decode(raw,pass)));
  }System.out.println(json(vectors));
 }
}

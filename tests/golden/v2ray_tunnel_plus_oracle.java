// Independent Java URI/Base64 oracle, normalized from this APK's Utils and *Fmt readers.
// Retains query pairs and VMess JSON intact instead of device-dependent defaults.
import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.util.*;
class v2ray_tunnel_plus_oracle {
 static String b64(String s){s=s.replaceAll("\\s","").replace('-','+').replace('_','/');return new String(Base64.getDecoder().decode(s),StandardCharsets.UTF_8);}
 static String form(String s)throws Exception{return URLDecoder.decode(s,StandardCharsets.UTF_8);}
 static String pct(String s)throws Exception{return form(s.replace("+","%2B"));}
 static String quote(String s){StringBuilder b=new StringBuilder("\"");for(char c:s.toCharArray()){if(c=='"'||c=='\\')b.append('\\').append(c);else if(c<32||c>126)b.append(String.format("\\u%04x",(int)c));else b.append(c);}return b.append('"').toString();}
 static String json(Object o){if(o==null)return "null";if(o instanceof String)return quote((String)o);if(o instanceof Map){List<String>a=new ArrayList<>();((Map<?,?>)o).forEach((k,v)->a.add(quote(k.toString())+":"+json(v)));return "{"+String.join(",",a)+"}";}if(o instanceof List){List<String>a=new ArrayList<>();for(Object v:(List<?>)o)a.add(json(v));return "["+String.join(",",a)+"]";}return o.toString();}
 static String profile(String source)throws Exception {
  String scheme=source.substring(0,source.indexOf("://")),body=source.substring(source.indexOf("://")+3);Map<String,Object>m=new LinkedHashMap<>();m.put("protocol",scheme);m.put("uri",source);
  if(scheme.equals("vmess")&&!body.contains("@"))return "{\"protocol\":\"vmess\",\"uri\":"+quote(source)+",\"encoding\":\"base64-json\",\"config\":"+b64(body)+"}";
  String parsed=source;
  if(scheme.equals("ss")&&!body.contains("@")){String[]p=body.split("#",2);parsed="ss://"+b64(p[0])+(p.length==2?"#"+p[1]:"");}
  URI u=new URI(parsed.replace(" ","%20").replace("|","%7C"));String host=u.getHost();if(host==null||u.getPort()<1)throw new IllegalArgumentException("URI");
  if(host.startsWith("["))host=host.substring(1,host.length()-1);
  String info=u.getRawUserInfo()==null?"":pct(u.getRawUserInfo());List<Object>pairs=new ArrayList<>();
  if(u.getRawQuery()!=null&&!u.getRawQuery().isEmpty())for(String p:u.getRawQuery().split("&",-1)){String[]kv=p.split("=",2);pairs.add(Arrays.asList(form(kv[0]),kv.length==2?form(kv[1]):""));}
  m.put("encoding","uri");m.put("host",host.toLowerCase(Locale.ROOT));m.put("port",u.getPort());m.put("userInfo",info);m.put("path",u.getPath()==null?"":u.getPath());m.put("query",pairs);m.put("fragment",u.getFragment()==null?"":form(u.getFragment()));
  if(scheme.equals("ss")||scheme.equals("socks")&&!info.isEmpty()){
   String c=scheme.equals("ss")&&info.contains(":")?info:b64(info);String[]v=c.split(":",2);Map<String,Object>cred=new LinkedHashMap<>();cred.put(scheme.equals("ss")?"method":"username",v[0]);cred.put("password",v[1]);m.put("credentials",cred);
  }
  return json(m);
 }
 public static void main(String[]args)throws Exception{BufferedReader in=new BufferedReader(new InputStreamReader(System.in,StandardCharsets.UTF_8));String l;while((l=in.readLine())!=null){String[]p=l.split("\t",2);String s=new String(Base64.getDecoder().decode(p[1]),StandardCharsets.UTF_8);String out=p[0].equals("base64")?b64(s):profile(s);System.out.println(Base64.getEncoder().encodeToString(out.getBytes(StandardCharsets.UTF_8)));}}
}

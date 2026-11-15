package com.ghostdeveloper.spdecode.admin;
import java.net.*;
import java.io.*;
import java.nio.charset.StandardCharsets;
import javax.net.ssl.*;
import java.security.cert.Certificate;

class NativeAdminRoutes {
 static {System.loadLibrary("spdecode_admin");}
 native byte[][] exchangeNative(byte[] operation,byte[] query,int page,byte[] body,byte[] cookie);
 static String mode="ok";static int opened=0,closed=0;static Fake last;
 static byte[] utf(String s){return s.getBytes(StandardCharsets.UTF_8);}
 static String str(byte[][] v,int i){return new String(v[i],StandardCharsets.UTF_8);}
 static class Fake extends HttpsURLConnection {
  ByteArrayOutputStream body=new ByteArrayOutputStream();
  Fake(URL u){super(u);}
  public void connect(){} public void disconnect(){closed++;} public boolean usingProxy(){return false;}
  public String getCipherSuite(){return "TLS_TEST_FIXTURE";}public Certificate[] getLocalCertificates(){return null;}public Certificate[] getServerCertificates(){return null;}
  public OutputStream getOutputStream(){return body;}
  public int getResponseCode(){return mode.equals("redirect")?302:mode.equals("denied")?403:200;}
  public String getHeaderFieldKey(int i){return i==1?"Set-Cookie":null;}
  public String getHeaderField(int i){return i==1?"spdecode_admin_session=synthetic.token; Secure; HttpOnly; Path=/api/admin; Max-Age=1800":null;}
  public InputStream getInputStream(){return mode.equals("large")?new ByteArrayInputStream(new byte[8*1024*1024+1]):new ByteArrayInputStream(utf("{\"text\":\"Hola 👻\"}"));}
  public InputStream getErrorStream(){return new ByteArrayInputStream(utf("{\"error\":{\"code\":\"FORBIDDEN\"}}"));}
 }
 public static void main(String[] args)throws Exception{
  URL.setURLStreamHandlerFactory(protocol->protocol.equals("https")?new URLStreamHandler(){protected URLConnection openConnection(URL url){opened++;return last=new Fake(url);}}:null);
  var nativeClient=new NativeAdminRoutes();
  var login=nativeClient.exchangeNative(utf("login"),utf(""),0,utf("{\"username\":\"synthetic\",\"password\":\"not-real\"}"),utf(""));
  if(!str(login,0).equals("200")||!last.getURL().toString().equals("https://panel.spdecode.xyz/api/admin/login")||last.getInstanceFollowRedirects()||!last.getRequestProperty("Origin").equals("https://panel.spdecode.xyz")||!last.getRequestMethod().equals("POST")||!last.body.toString(StandardCharsets.UTF_8).contains("synthetic")||!str(login,2).contains("Secure"))throw new AssertionError("HTTPS request contract");
  int count=opened;
  if(!str(nativeClient.exchangeNative(utf("session"),utf(""),0,utf(""),utf("spdecode_admin_session=x\r\nInject:x")),0).equals("0")||opened!=count)throw new AssertionError("cookie injection");
  if(!str(nativeClient.exchangeNative(utf("session"),utf(""),0,utf(""),utf("")),0).equals("401")||opened!=count)throw new AssertionError("unauthenticated network request");
  var response=nativeClient.exchangeNative(utf("session"),utf(""),0,utf(""),utf("spdecode_admin_session=synthetic.token"));
  if(!str(response,1).contains("👻"))throw new AssertionError("UTF-8 response corrupted");
  mode="redirect";if(!str(nativeClient.exchangeNative(utf("session"),utf(""),0,utf(""),utf("spdecode_admin_session=x.y")),1).equals("REDIRECT_REJECTED"))throw new AssertionError("redirect accepted");
  mode="denied";response=nativeClient.exchangeNative(utf("session"),utf(""),0,utf(""),utf("spdecode_admin_session=x.y"));if(!str(response,0).equals("403")||!str(response,1).contains("FORBIDDEN"))throw new AssertionError("error body discarded");
  mode="large";if(!str(nativeClient.exchangeNative(utf("session"),utf(""),0,utf(""),utf("spdecode_admin_session=x.y")),1).equals("RESPONSE_TOO_LARGE"))throw new AssertionError("response limit ignored");
  if(closed!=opened)throw new AssertionError("connection leak");
  System.out.println("PASS native HTTPS origin, POST body/headers, session guard, redirect rejection, UTF-8, errors, limits and disconnect");
 }
}

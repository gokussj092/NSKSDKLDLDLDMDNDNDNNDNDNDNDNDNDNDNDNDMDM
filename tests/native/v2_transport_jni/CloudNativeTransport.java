package com.ghostdeveloper.spdecode.cloud;

import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.security.cert.Certificate;
import javax.net.ssl.HttpsURLConnection;

/** Real native bridge with mocked TLS, not a certificate verification test. */
public final class CloudNativeTransport {
    static { System.load(System.getProperty("spdecode.native")); }
    private static native String postNative(int operation,String json,String bearer,
        String version,String timestamp,String nonce,String proof,String actionChallenge,String actionIntegrity) throws IOException;
    private static FakeConnection last;
    private static boolean failUpload;
    private static final String RESPONSE="{\"message\":\"México 👻 漢字\"}";
    private static final class FakeConnection extends HttpsURLConnection {
        final ByteArrayOutputStream output=new ByteArrayOutputStream();
        FakeConnection(URL url){super(url);}
        public void connect(){} public void disconnect(){}
        public boolean usingProxy(){return false;}
        public String getCipherSuite(){return "synthetic";}
        public Certificate[] getLocalCertificates(){return null;}
        public Certificate[] getServerCertificates(){return new Certificate[0];}
        public OutputStream getOutputStream() throws IOException {if(failUpload)throw new IOException("synthetic upload failure");return output;}
        public InputStream getInputStream(){return new ByteArrayInputStream(RESPONSE.getBytes(StandardCharsets.UTF_8));}
        public int getResponseCode(){return 200;}
    }
    private static void check(boolean value,String message){if(!value)throw new AssertionError(message);}
    public static void main(String[] args)throws Exception {
        URL.setURLStreamHandlerFactory(protocol->protocol.equals("https")?new URLStreamHandler(){
            protected URLConnection openConnection(URL url){return last=new FakeConnection(url);}
        }:null);
        String body="{\"text\":\"México 👻 漢字\",\"zero\":\"\\u0000\"}";
        String timestamp="1700000000",nonce="AAECAwQFBgcICQoLDA0ODxAREhMUFRYX",proof="A".repeat(96);
        check(postNative(6,body,"synthetic.bearer","1.1.22",timestamp,nonce,proof,"","").equals("200\n"+RESPONSE),"UTF-8 reply changed");
        check(last.output.toString(StandardCharsets.UTF_8).equals(body),"Uploaded UTF-8 changed");
        check(last.getURL().toString().equals("https://api.spdecode.example/api/v2/transport"),"Wrong destination");
        check(last.getRequestProperty("X-SP-Operation").equals("6"),"Wrong operation");
        check(last.getRequestProperty("X-SP-Proof").equals(proof),"Wrong proof");
        check(last.getRequestProperty("X-SP-Nonce").equals(nonce),"Wrong nonce");
        check(last.getRequestProperty("X-SP-Timestamp").equals(timestamp),"Wrong timestamp");
        check(last.getRequestProperty("Authorization").equals("Bearer synthetic.bearer"),"Wrong bearer");
        check(!last.getInstanceFollowRedirects(),"Redirects allowed");
        check(last.getReadTimeout()==25000,"Ordinary budget changed");
        String actionId="00000000-0000-4000-8000-000000000001",actionToken="A".repeat(100);
        postNative(6,body,"synthetic.bearer","1.1.23",timestamp,nonce,proof,actionId,actionToken);
        check(last.getRequestProperty("X-SP-Action-Challenge").equals(actionId),"Wrong action challenge");
        check(last.getRequestProperty("X-SP-Action-Integrity").equals(actionToken),"Wrong action integrity");
        try {postNative(6,body,"","1.1.23",timestamp,nonce,proof,actionId,actionToken+"\r\n");throw new AssertionError("Header injection accepted");}
        catch(IOException expected){check(expected.getMessage().equals("CLOUD_NATIVE_REQUEST_REJECTED"),"Wrong header rejection");}

        postNative(9,"{}","synthetic.bearer","1.1.22",timestamp,nonce,proof,"","");
        check(last.getReadTimeout()==165000,"Catalog budget changed");
        postNative(5,"{\"compatibleExport\":{}}","synthetic.bearer","1.1.22",timestamp,nonce,proof,"","");
        check(last.getReadTimeout()==55000,"Export budget changed");
        try {postNative(3,body,"","1.1.22",timestamp,nonce,proof,"","");throw new AssertionError("Reserved op accepted");}
        catch(IOException expected){check(expected.getMessage().equals("CLOUD_NATIVE_REQUEST_REJECTED"),"Wrong rejection");}
        failUpload=true;
        try {postNative(6,body,"","1.1.22",timestamp,nonce,proof,"","");throw new AssertionError("Upload failure accepted");}
        catch(IOException expected){check(expected.getMessage().equals("CLOUD_NATIVE_NETWORK_UNAVAILABLE"),"Wrong network failure");}
        finally {failUpload=false;}
        System.out.println("Real JNI registration, UTF-8, proof headers, destination, budgets and pending-exception cleanup passed");
    }
}


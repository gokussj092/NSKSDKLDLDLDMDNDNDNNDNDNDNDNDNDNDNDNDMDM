package com.ghostdeveloper.spdecode.results;
import java.nio.charset.StandardCharsets;
import java.io.ByteArrayOutputStream;
import java.util.Arrays;
/** Host JNI contract fixture; no Android startup or APK build. */
class NativeResultEngine {
 static native long nativeOpen(String raw)throws java.io.IOException;
 static native int nativeLength(long handle);
 static native byte[] nativePage(long handle,int parent,int offset,int limit,boolean mask)throws java.io.IOException;
 static native byte[] nativeValue(long handle,int node,int offset,int limit,boolean mask);
 static native byte[] nativeOriginal(long handle,int offset,int limit);
 static native void nativeClose(long handle);
 public static void main(String[]args)throws Exception{
  System.load(args[0]);
  String raw="{\"password\":\"fictional-private\",\"name\":\""+"a".repeat(4059)+"🌎\"}";
  long handle=nativeOpen(raw);if(nativeLength(handle)!=raw.getBytes(StandardCharsets.UTF_8).length)throw new AssertionError("length");
  for(int i=0;i<100;i++){
   String masked=new String(nativePage(handle,0,0,64,true),StandardCharsets.UTF_8);
   if(masked.contains("fictional-private"))throw new AssertionError("privacy");
   String clear=new String(nativePage(handle,0,0,64,false),StandardCharsets.UTF_8);
   if(!clear.contains("fictional-private"))throw new AssertionError("reveal");
  }
  ByteArrayOutputStream out=new ByteArrayOutputStream();for(int i=0;i<nativeLength(handle);i+=1024)out.write(nativeOriginal(handle,i,1024));
  if(!Arrays.equals(out.toByteArray(),raw.getBytes(StandardCharsets.UTF_8)))throw new AssertionError("export");
  nativeClose(handle);nativeClose(handle);
  try{nativePage(handle,0,0,64,false);throw new AssertionError("closed handle");}catch(java.io.IOException expected){}
  try{nativeOpen("{\"broken\":}");throw new AssertionError("invalid input");}catch(java.io.IOException expected){}
  System.out.println("JNI unicode length / 100 privacy toggles / exact original / close / invalid: PASS");
 }
}

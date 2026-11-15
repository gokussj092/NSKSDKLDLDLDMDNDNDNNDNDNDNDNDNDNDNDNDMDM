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
 static native int nativeLineCount(long handle);
 static native int nativeColumnCount(long handle);
 static native byte[] nativeLineWindow(long handle,int line,int column,int count,boolean mask);
 static native int nativeFindNext(long handle,byte[] term,int start,boolean mask);
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
  if(nativeLineCount(handle)!=4)throw new AssertionError("logical line count");
  if(nativeColumnCount(handle)<4000)throw new AssertionError("full line width");
  if(nativeFindNext(handle,"fictional-private".getBytes(StandardCharsets.UTF_8),0,true)!=-1)
    throw new AssertionError("masked search leak");
  if(nativeFindNext(handle,"FICTIONAL-PRIVATE".getBytes(StandardCharsets.UTF_8),0,false)!=1)
    throw new AssertionError("case-insensitive find");
  if(nativeFindNext(handle,"name".getBytes(StandardCharsets.UTF_8),0,true)!=2)
    throw new AssertionError("full document search");
  String hiddenLine=new String(nativeLineWindow(handle,1,0,128,true),StandardCharsets.UTF_8);
  if(hiddenLine.contains("fictional-private")||!hiddenLine.contains("••••••••"))throw new AssertionError("line privacy");
  String lineEnd=new String(nativeLineWindow(handle,2,4000,128,false),StandardCharsets.UTF_8);
  if(!lineEnd.contains("🌎"))throw new AssertionError("complete long line");
  nativeClose(handle);nativeClose(handle);
  try{nativePage(handle,0,0,64,false);throw new AssertionError("closed handle");}catch(java.io.IOException expected){}
  try{nativeOpen("{\"broken\":}");throw new AssertionError("invalid input");}catch(java.io.IOException expected){}
  for(int count:new int[]{8000,20000,50000}){
   StringBuilder array=new StringBuilder("[");
   for(int i=0;i<count;i++){if(i>0)array.append(',');array.append("{\"id\":").append(i).append('}');}
   array.append(']');long large=nativeOpen(array.toString());
   if(nativeLineCount(large)!=3*count+2)throw new AssertionError("large line count");
   String tail=new String(nativeLineWindow(large,3*count-1,0,128,false),StandardCharsets.UTF_8);
   if(!tail.contains(Integer.toString(count-1)))throw new AssertionError("last record");
   nativeClose(large);
  }
  System.out.println("JNI complete lines / 50k records / Unicode / privacy / exact original / close / invalid: PASS");
 }
}


#!/usr/bin/env sh
set -eu
here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
root="$here/../app/src/main/cpp"
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
JAVA_HOME=${JAVA_HOME:-$(dirname "$(dirname "$(readlink -f "$(command -v javac)")")")}
${CXX:-c++} -std=c++17 -Wall -Wextra -Werror -pedantic -shared -fPIC -fvisibility=hidden -I"$JAVA_HOME/include" -I"$JAVA_HOME/include/linux" "$root/admin_routes.cpp" "$root/admin_jni.cpp" -o "$work/libspdecode_admin.so"
cat > "$work/NativeAdminRoutes.java" <<'JAVA'
package com.ghostdeveloper.spdecode.admin;
import java.nio.charset.StandardCharsets;
public class NativeAdminRoutes {
    static {System.loadLibrary("spdecode_admin");}
    private native String[] planNative(byte[] op,byte[] query,int page,int bodySize);
    private String[] plan(String op,String query,int page,int size){return planNative(op.getBytes(StandardCharsets.UTF_8),query.getBytes(StandardCharsets.UTF_8),page,size);}
    public static void main(String[] args){
        NativeAdminRoutes routes=new NativeAdminRoutes();
        String[] p=routes.plan("users","a&ñ",2,0);
        if(p==null || !p[0].equals("/api/admin/users?page=2&q=a%26%C3%B1") || !p[1].equals("GET")) throw new AssertionError("bad plan");
        if(routes.plan("maintenance","",0,10)!=null || routes.plan("login","",0,-1)!=null) throw new AssertionError("rejected route accepted");
        System.out.println("PASS host JNI shared library, symbol load and UTF-8 query encoding");
    }
}
JAVA
"$JAVA_HOME/bin/javac" -d "$work" "$work/NativeAdminRoutes.java"
"$JAVA_HOME/bin/java" -Djava.library.path="$work" -cp "$work" com.ghostdeveloper.spdecode.admin.NativeAdminRoutes

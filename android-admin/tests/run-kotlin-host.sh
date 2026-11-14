#!/usr/bin/env sh
set -eu
here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
root="$here/../app/src/main"
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
JAVA_HOME=${JAVA_HOME:-$(dirname "$(dirname "$(readlink -f "$(command -v javac)")")")}
c++ -std=c++17 -Wall -Wextra -Werror -pedantic -shared -fPIC -fvisibility=hidden -I"$JAVA_HOME/include" -I"$JAVA_HOME/include/linux" "$root/cpp/admin_routes.cpp" "$root/cpp/admin_jni.cpp" -o "$work/libspdecode_admin.so"
cat > "$work/Check.kt" <<'KOTLIN'
package com.ghostdeveloper.spdecode.admin
fun main(){
    check(NativeAdminRoutes.plan("users","a&ñ",2).path=="/api/admin/users?page=2&q=a%26%C3%B1")
    check(NativeAdminRoutes.plan("login",bodySize=100).method=="POST")
    for(op in listOf("maintenance","https://example.com","../login")) check(runCatching{NativeAdminRoutes.plan(op)}.isFailure)
    check(runCatching{NativeAdminRoutes.plan("users","x".repeat(81))}.isFailure)
    println("PASS Kotlin object → JNI → C++ route planner")
}
KOTLIN
KOTLIN_STDLIB=${KOTLIN_STDLIB:-$(dirname "$(dirname "$(readlink -f "$(command -v kotlinc)")")")/lib/kotlin-stdlib.jar}
test -f "$KOTLIN_STDLIB"
kotlinc "$root/java/com/ghostdeveloper/spdecode/admin/NativeAdminRoutes.kt" "$work/Check.kt" -d "$work/check.jar"
"$JAVA_HOME/bin/java" -Djava.library.path="$work" -cp "$work/check.jar:$KOTLIN_STDLIB" com.ghostdeveloper.spdecode.admin.CheckKt

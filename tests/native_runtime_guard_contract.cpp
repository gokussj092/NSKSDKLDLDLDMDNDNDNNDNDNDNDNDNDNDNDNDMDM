#include "../android/app/src/main/cpp/spdecode_runtime_guard.h"
#include <cassert>
#include <iostream>
#include <string>
int main(){
    using spdecode::runtimeRiskFromProc;
    const std::string clean="Name:\tapp\nTracerPid:\t0\n";
    const std::string map="7d-8a r-xp 00:00 0 /data/app/lib/other.so\n";
    assert(runtimeRiskFromProc(clean,map)==0);
    assert(runtimeRiskFromProc("TracerPid:\t512\n",map)==1);
    assert(runtimeRiskFromProc(clean,map+"7d-8a r-xp 0 0 /data/user/libfrida-gadget.so\n")==2);
    assert(runtimeRiskFromProc("TracerPid: 2\n","7d /libxposed_art.so\n")==3);
    assert(runtimeRiskFromProc(clean,"7d /data/user/frida-gadget-not-loaded.txt")==0);
    assert(runtimeRiskFromProc(clean,"7d /data/user/vendor/libssl.so")==0);
    std::cout<<"PASS narrow native runtime instrumentation risk signals\n";
}

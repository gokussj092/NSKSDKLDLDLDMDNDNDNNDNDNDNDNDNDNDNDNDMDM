#include "../android/app/src/main/cpp/spdecode_runtime_guard.h"
#include <cassert>
#include <iostream>
#include <string>

int main() {
    using spdecode::runtimeRiskFromProc;
    const std::string clean = "Name:\tspdecode\nTracerPid:\t0\n";
    const std::string ordinaryMap = "7d-8a r-xp 00000000 00:00 0 /data/app/lib/other.so\n";

    // R0 false-positive baseline: legitimate developer and VPN tooling must
    // not be treated as in-process instrumentation without direct evidence.
    assert(runtimeRiskFromProc(clean, ordinaryMap) == 0);
    assert(runtimeRiskFromProc(clean, ordinaryMap +
        "7d-8a r-xp 0 0 /data/app/com.termux/libtermux.so\n") == 0);
    assert(runtimeRiskFromProc(clean, ordinaryMap +
        "7d-8a r-xp 0 0 /data/app/moe.shizuku.privileged.api/libshizuku.so\n") == 0);
    assert(runtimeRiskFromProc(clean, ordinaryMap +
        "7d-8a r-xp 0 0 /data/app/com.example.vpn/libvpn.so\n") == 0);
    assert(runtimeRiskFromProc("Name:\tspdecode\nTracerPid:\t0\nAdbEnabled:\t1\n", ordinaryMap) == 0);
    assert(runtimeRiskFromProc(clean,
        "7d-8a r-xp 0 0 /data/user/frida-gadget-not-loaded.txt\n") == 0);

    // Synthetic direct indicators of instrumentation of THIS process.
    assert(runtimeRiskFromProc("TracerPid:\t512\n", ordinaryMap) == 1);
    assert(runtimeRiskFromProc(clean, ordinaryMap +
        "7d-8a r-xp 0 0 /data/user/libfrida-gadget.so\n") == 2);
    assert(runtimeRiskFromProc(clean,
        "7d-8a r-xp 0 0 /data/user/LIBFRIDA-GADGET.SO\n") == 2);
    assert(runtimeRiskFromProc("TracerPid: 2\n",
        "7d-8a r-xp 0 0 /data/user/libxposed_art.so\n") == 3);
    assert(runtimeRiskFromProc(clean,
        "7d-8a r-xp 0 0 /data/user/libcydia_substrate.so\n") == 2);

    // Partial/inaccessible proc snapshots are not positive proof of attack.
    // R2 must model these as UNKNOWN instead of interpreting zero as verified clean.
    assert(runtimeRiskFromProc("", "") == 0);
    assert(runtimeRiskFromProc("TracerPid: unavailable\n", ordinaryMap) == 0);
    assert(runtimeRiskFromProc("TracerPid: -1\n", ordinaryMap) == 0);
    assert(runtimeRiskFromProc("Name:\tspdecode\n", ordinaryMap) == 0);

    std::cout << "PASS R0 native RASP baseline: explicit hook/tracer and benign-tool controls\n";
}

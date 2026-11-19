// Host-side test harness for the offline native TLS Tunnel decoder.
// Builds the exact production source (spdecode_tls_tunnel.cpp) with the
// system compiler so the .tls path can be exercised against synthetic
// fixtures without an Android NDK/Gradle build. Prints decoded JSON on
// stdout; on failure prints "ERROR <what>" on stderr and exits non-zero,
// mirroring the JNI error strings the offline app surfaces (TLS_*).
#include "spdecode_tls_tunnel.h"

#include <cstdio>
#include <fstream>
#include <iostream>
#include <string>
#include <vector>

int main(int argc, char** argv) {
    if (argc != 2) {
        std::cerr << "usage: tls_harness <file.tls|file.txt>\n";
        return 3;
    }
    std::ifstream in(argv[1], std::ios::binary);
    if (!in) {
        std::cerr << "ERROR TLS_CANNOT_OPEN_INPUT\n";
        return 3;
    }
    std::vector<unsigned char> raw((std::istreambuf_iterator<char>(in)),
                                   std::istreambuf_iterator<char>());
    try {
        std::cout << spdecode::offline::decodeTls(raw) << "\n";
    } catch (const std::exception& error) {
        std::cerr << "ERROR " << error.what() << "\n";
        return 1;
    }
    return 0;
}

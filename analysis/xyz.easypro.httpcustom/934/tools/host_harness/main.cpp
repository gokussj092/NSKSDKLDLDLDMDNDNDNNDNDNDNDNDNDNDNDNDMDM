// Host-side test harness for the offline native HTTP Custom decoder.
// Builds the exact production sources (spdecode_http_custom.cpp +
// spdecode_http_custom_legacy.cpp) with the system compiler so the n15
// path can be exercised against real .hc samples without an Android
// NDK/Gradle build. Prints decoded JSON on stdout; on failure prints
// "ERROR <what>" on stderr and exits non-zero, mirroring the JNI error
// strings the offline app surfaces (HC_*, PASSWORD_REQUIRED, ...).
#include "spdecode_http_custom.h"

#include <cstdio>
#include <fstream>
#include <iostream>
#include <string>
#include <vector>

int main(int argc, char** argv) {
    if (argc < 2 || argc > 4) {
        std::cerr << "usage: hc_harness <file.hc> [password] [hwid]\n";
        return 3;
    }
    std::ifstream in(argv[1], std::ios::binary);
    if (!in) {
        std::cerr << "ERROR HC_CANNOT_OPEN_INPUT\n";
        return 3;
    }
    std::vector<unsigned char> raw((std::istreambuf_iterator<char>(in)),
                                   std::istreambuf_iterator<char>());
    const std::string password = argc >= 3 ? argv[2] : std::string();
    const std::string hwid = argc >= 4 ? argv[3] : std::string();
    try {
        std::cout << spdecode::offline::decodeHttpCustom(raw, password, hwid);
    } catch (const std::exception& error) {
        std::cerr << "ERROR " << error.what() << "\n";
        return 1;
    }
    return 0;
}

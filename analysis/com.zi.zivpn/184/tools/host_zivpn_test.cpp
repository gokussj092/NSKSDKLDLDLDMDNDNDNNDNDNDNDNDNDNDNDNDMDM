// Host test for the OFFLINE native ZIVPN decoder.
//
// Compiles the production file android/app/src/main/cpp/spdecode_zivpn.cpp
// UNCHANGED against Mbed TLS 3.6.7 (the version pinned by
// android/app/src/main/cpp/CMakeLists.txt) and nlohmann json, then checks
// it against the synthetic fixtures in tests/fixtures/ plus FIPS known
// answer tests for the underlying DES/AES primitives. No network, no
// device, no secrets beyond the app-embedded format constants already in
// the production file. Build with tools/build_host_harness.sh.
//
// Usage: host_zivpn_test <fixtures-dir>
#include "spdecode_zivpn.cpp"

#include <mbedtls/aes.h>
#include <mbedtls/des.h>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

namespace {
using Bytes = std::vector<unsigned char>;
int failures = 0;
int passes = 0;

void pass(const std::string& name) {
    passes++;
    std::cout << "PASS " << name << "\n";
}
void fail(const std::string& name, const std::string& detail) {
    failures++;
    std::cout << "FAIL " << name << ": " << detail << "\n";
}

std::string readFile(const std::string& path) {
    std::ifstream in(path, std::ios::binary);
    if (!in) throw std::runtime_error("cannot read " + path);
    std::ostringstream ss;
    ss << in.rdbuf();
    return ss.str();
}
Bytes readBytes(const std::string& path) {
    const std::string text = readFile(path);
    return Bytes(text.begin(), text.end());
}
nlohmann::json readJson(const std::string& path) {
    return nlohmann::json::parse(readFile(path));
}

std::string hex(const unsigned char* data, size_t size) {
    static constexpr char alphabet[] = "0123456789abcdef";
    std::string out;
    for (size_t i = 0; i < size; i++) {
        out.push_back(alphabet[data[i] >> 4]);
        out.push_back(alphabet[data[i] & 15]);
    }
    return out;
}
Bytes unhex(const char* text) {
    Bytes out;
    for (size_t i = 0; text[i] && text[i + 1]; i += 2) {
        auto nibble = [](char c) -> int {
            if (c >= '0' && c <= '9') return c - '0';
            if (c >= 'a' && c <= 'f') return c - 'a' + 10;
            return c - 'A' + 10;
        };
        out.push_back(static_cast<unsigned char>((nibble(text[i]) << 4) | nibble(text[i + 1])));
    }
    return out;
}

void expectFile(const std::string& dir, const std::string& fixture,
                const std::string& expectedName) {
    const std::string name = "file " + fixture;
    try {
        const std::string out = spdecode::offline::decodeZiv(readBytes(dir + "/" + fixture));
        const nlohmann::json got = nlohmann::json::parse(out);
        const nlohmann::json want = readJson(dir + "/" + expectedName);
        if (got == want) pass(name);
        else fail(name, "got " + out);
    } catch (const std::exception& e) {
        fail(name, e.what());
    }
}

void expectText(const std::string& dir, const std::string& fixture,
                const std::string& expectedName) {
    const std::string name = "text " + fixture;
    try {
        const std::string out =
            spdecode::offline::decodeZivpnText(readBytes(dir + "/" + fixture));
        const nlohmann::json got = nlohmann::json::parse(out);
        const nlohmann::json want = readJson(dir + "/" + expectedName);
        if (got == want) pass(name);
        else fail(name, "got " + out);
    } catch (const std::exception& e) {
        fail(name, e.what());
    }
}

void expectFileFails(const std::string& dir, const std::string& fixture,
                     const std::string& label) {
    const std::string name = "negative file " + label;
    try {
        const std::string out = spdecode::offline::decodeZiv(readBytes(dir + "/" + fixture));
        fail(name, "decoded unexpectedly: " + out);
    } catch (const std::exception&) {
        pass(name);
    }
}

void expectTextFails(const std::string& label, const std::string& input) {
    const std::string name = "negative text " + label;
    try {
        const Bytes raw(input.begin(), input.end());
        const std::string out = spdecode::offline::decodeZivpnText(raw);
        fail(name, "decoded unexpectedly: " + out);
    } catch (const std::exception&) {
        pass(name);
    }
}

void expectFileFailsRaw(const std::string& label, const std::string& input) {
    const std::string name = "negative file " + label;
    try {
        const Bytes raw(input.begin(), input.end());
        const std::string out = spdecode::offline::decodeZiv(raw);
        fail(name, "decoded unexpectedly: " + out);
    } catch (const std::exception&) {
        pass(name);
    }
}
}  // namespace

int main(int argc, char** argv) {
    if (argc != 2) {
        std::cerr << "usage: host_zivpn_test <fixtures-dir>\n";
        return 2;
    }
    const std::string dir = argv[1];

    // FIPS 46-3 DES known answer (ECB): key 133457799BBCDFF1,
    // plaintext 0123456789ABCDEF -> 85E813540F0AB405.
    {
        const Bytes key = unhex("133457799BBCDFF1");
        const Bytes pt = unhex("0123456789ABCDEF");
        unsigned char out[8] = {};
        mbedtls_des_context ctx;
        mbedtls_des_init(&ctx);
        int rc = mbedtls_des_setkey_enc(&ctx, key.data());
        if (rc == 0) rc = mbedtls_des_crypt_ecb(&ctx, pt.data(), out);
        mbedtls_des_free(&ctx);
        if (rc == 0 && hex(out, 8) == "85e813540f0ab405") pass("FIPS 46-3 DES-ECB vector");
        else fail("FIPS 46-3 DES-ECB vector", rc == 0 ? hex(out, 8) : "mbedtls error");
    }
    // FIPS 197 AES-128 known answer (ECB): key 000102...0f,
    // plaintext 001122...ff -> 69c4e0d86a7b0430d8cdb78070b4c55a.
    {
        const Bytes key = unhex("000102030405060708090a0b0c0d0e0f");
        const Bytes pt = unhex("00112233445566778899aabbccddeeff");
        unsigned char out[16] = {};
        mbedtls_aes_context ctx;
        mbedtls_aes_init(&ctx);
        int rc = mbedtls_aes_setkey_enc(&ctx, key.data(), 128);
        if (rc == 0) rc = mbedtls_aes_crypt_ecb(&ctx, MBEDTLS_AES_ENCRYPT, pt.data(), out);
        mbedtls_aes_free(&ctx);
        if (rc == 0 && hex(out, 16) == "69c4e0d86a7b0430d8cdb78070b4c55a")
            pass("FIPS 197 AES-128 vector");
        else fail("FIPS 197 AES-128 vector", rc == 0 ? hex(out, 16) : "mbedtls error");
    }

    expectFile(dir, "ziv-legacy.ziv", "ziv-legacy.expected.json");
    expectFile(dir, "ziv-export.ziv", "ziv-export.expected.json");
    expectFile(dir, "ziv-legacy-password.ziv", "ziv-legacy-password.expected.json");
    expectFile(dir, "ziv-golden.ziv", "ziv-golden.expected.json");
    expectFile(dir, "ziv-plain.xml", "ziv-plain.expected.json");
    expectText(dir, "zivpn-link.txt", "zivpn-link.expected.json");
    expectText(dir, "zivpn-json-link.txt", "zivpn-json-link.expected.json");
    // Same text link without the scheme prefix must also decode.
    {
        const std::string token = readFile(dir + "/zivpn-link.txt");
        const std::string bare = token.substr(std::string("zivpn://").size());
        const std::string name = "text zivpn-link bare token";
        try {
            const Bytes raw(bare.begin(), bare.end());
            const std::string out = spdecode::offline::decodeZivpnText(raw);
            if (nlohmann::json::parse(out) == readJson(dir + "/zivpn-link.expected.json"))
                pass(name);
            else fail(name, "got " + out);
        } catch (const std::exception& e) {
            fail(name, e.what());
        }
    }

    expectFileFails(dir, "ziv-wrong-password.ziv", "wrong password");
    expectFileFails(dir, "ziv-tampered-tag.ziv", "tampered GCM tag");
    expectFileFailsRaw("empty", "");
    expectFileFailsRaw("not a profile", "NOT A PROFILE");
    expectFileFailsRaw("two parts", "AAAA.AAAA");
    expectFileFailsRaw("bad base64", "!!!.!!!.!!!");
    expectTextFails("empty", "");
    expectTextFails("not base64", "zivpn://!!");
    expectTextFails("short block", "zivpn://AAAA");

    std::cout << "host_zivpn_test: " << passes << " passed, " << failures << " failed\n";
    return failures == 0 ? 0 : 1;
}

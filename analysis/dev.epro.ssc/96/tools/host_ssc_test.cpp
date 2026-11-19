// Host test for the OFFLINE native SSC decoder.
//
// Compiles the production file android/app/src/main/cpp/spdecode_ssc.cpp
// UNCHANGED against nlohmann json, then checks it against the synthetic
// fixtures in tests/fixtures/ plus a ChaCha20 known-answer vector for the
// underlying primitive. No network, no device, no secrets beyond the
// app-embedded format constants already in the production file.
// Build with tools/build_host_harness.sh.
//
// Usage: host_ssc_test <fixtures-dir> <expected-dir>
#include "spdecode_ssc.cpp"

#include <cstdio>
#include <cstring>
#include <fstream>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

namespace {
using Bytes = std::vector<unsigned char>;
using json = nlohmann::ordered_json;
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

std::string hexOf(const Bytes& data) {
    static constexpr char kDigits[] = "0123456789abcdef";
    std::string out;
    for (unsigned char b : data) {
        out.push_back(kDigits[b >> 4]);
        out.push_back(kDigits[b & 15]);
    }
    return out;
}
bool fromHexStr(const std::string& text, Bytes& out) {
    if (text.size() % 2 != 0) return false;
    out.clear();
    auto val = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    };
    for (size_t i = 0; i < text.size(); i += 2) {
        const int hi = val(text[i]);
        const int lo = val(text[i + 1]);
        if (hi < 0 || lo < 0) return false;
        out.push_back(static_cast<unsigned char>((hi << 4) | lo));
    }
    return true;
}

// Deep-compare two JSON values; report the first differing path.
bool jsonEqual(const json& got, const json& want, const std::string& path,
               std::string& detail) {
    if (got.type() != want.type()) {
        detail = path + ": type got " + std::string(got.type_name()) +
                 " want " + want.type_name();
        return false;
    }
    if (got.is_object()) {
        if (got.size() != want.size()) {
            detail = path + ": object size got " +
                     std::to_string(got.size()) + " want " +
                     std::to_string(want.size());
            return false;
        }
        for (auto it = want.begin(); it != want.end(); ++it) {
            if (!got.contains(it.key())) {
                detail = path + ": missing key " + it.key();
                return false;
            }
            if (!jsonEqual(got[it.key()], it.value(),
                           path + "/" + it.key(), detail))
                return false;
        }
        return true;
    }
    if (got.is_array()) {
        if (got.size() != want.size()) {
            detail = path + ": array size got " + std::to_string(got.size()) +
                     " want " + std::to_string(want.size());
            return false;
        }
        for (size_t i = 0; i < got.size(); i++)
            if (!jsonEqual(got[i], want[i],
                           path + "[" + std::to_string(i) + "]", detail))
                return false;
        return true;
    }
    if (got != want) {
        detail = path + ": got " + got.dump() + " want " + want.dump();
        return false;
    }
    return true;
}

void checkDecode(const std::string& fixtures, const std::string& expectedDir,
                 const std::string& name, const std::string& suffix) {
    const Bytes raw = readBytes(fixtures + "/" + name + suffix);
    const json want = json::parse(readFile(expectedDir + "/" + name + ".json"));
    std::string out;
    try {
        out = spdecode::offline::decodeSsc(raw);
    } catch (const std::exception& e) {
        fail(name, std::string("threw ") + e.what());
        return;
    }
    json got;
    try {
        got = json::parse(out);
    } catch (const std::exception& e) {
        fail(name, std::string("output is not JSON: ") + e.what());
        return;
    }
    std::string detail;
    if (jsonEqual(got, want, name, detail))
        pass(name);
    else
        fail(name, detail);
}

void checkReject(const std::string& fixtures, const std::string& name) {
    const Bytes raw = readBytes(fixtures + "/" + name + ".ssc");
    try {
        const std::string out = spdecode::offline::decodeSsc(raw);
        fail(name, "accepted invalid input, returned " + out.substr(0, 80));
    } catch (const std::exception&) {
        pass(name + "/rejects");
    }
}

void checkKat(const std::string& fixtures, const std::string& expectedDir) {
    const json kat = json::parse(readFile(expectedDir + "/chacha20_kat.json"));
    Bytes key, nonce, cipher, plain;
    if (!fromHexStr(kat["key_hex"].get<std::string>(), key) ||
        !fromHexStr(kat["nonce_hex"].get<std::string>(), nonce) ||
        !fromHexStr(kat["ciphertext_hex"].get<std::string>(), cipher) ||
        !fromHexStr(kat["plaintext_hex"].get<std::string>(), plain)) {
        fail("chacha20_kat", "bad hex in KAT file");
        return;
    }
    const Bytes got = spdecode::offline::chacha20_64(key, nonce, cipher);
    if (got == plain) {
        pass("chacha20_kat");
    } else {
        fail("chacha20_kat", "got " + hexOf(got) + " want " + hexOf(plain));
    }
    // The KAT ciphertext is not a valid SSC file: it must be rejected.
    try {
        spdecode::offline::decodeSsc(cipher);
        fail("chacha20_kat/not-a-file", "raw KAT bytes accepted as .ssc");
    } catch (const std::exception&) {
        pass("chacha20_kat/not-a-file");
    }
    (void)fixtures;
}

}  // namespace

int main(int argc, char** argv) {
    if (argc != 3) {
        std::cerr << "usage: host_ssc_test <fixtures-dir> <expected-dir>\n";
        return 2;
    }
    const std::string fixtures = argv[1];
    const std::string expectedDir = argv[2];
    try {
        checkDecode(fixtures, expectedDir, "single_layer", ".ssc");
        checkDecode(fixtures, expectedDir, "two_layer", ".ssc");
        checkDecode(fixtures, expectedDir, "inner_encrypted", ".ssc");
        checkDecode(fixtures, expectedDir, "ssc_link", ".txt");
        checkKat(fixtures, expectedDir);
        checkReject(fixtures, "truncated");
        checkReject(fixtures, "bad_hex");
        checkReject(fixtures, "garbage");
        checkReject(fixtures, "empty");
        checkReject(fixtures, "odd_hex");
        checkReject(fixtures, "valid_l1_no_json");
    } catch (const std::exception& e) {
        std::cout << "FAIL harness: " << e.what() << "\n";
        failures++;
    }
    std::cout << "host_ssc_test: " << passes << " passed, " << failures
              << " failed\n";
    return failures ? 1 : 0;
}

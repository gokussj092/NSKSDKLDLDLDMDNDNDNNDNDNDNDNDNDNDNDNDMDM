// SSC Custom (dev.epro.ssc, 4.3.13 / versionCode 96) - offline decoder.
//
// File format (.ssc) and text format (ssc://), per
// decoders/Python/SSCCUSTOM.py and the A23 golden generator:
//   file text = hex of the L1 ciphertext (whitespace ignored), or
//   "ssc://" + reversed(hex) for text links.
//   L1: ChaCha20(key=L1, nonce=FIXED_NONCE, counter=1) -> JSON text.
//       Original DJB ChaCha20: 64-bit nonce, 64-bit block counter.
//       NOT the IETF 96-bit-nonce variant (mbedtls_chacha20_crypt);
//       implemented here directly, mirroring parity/LegacyChaCha8.kt.
//   Single layer: L1 JSON has "a" = list of config objects.
//   Two layers:  L1 JSON has "a" = 16 hex chars (L2 nonce, 8 bytes)
//       and "c" = hex of the L2 ciphertext; L2 is ChaCha20(L2, nonce, 1).
//   Inner fields: a config object's "b" is a 32-char hex user key;
//       inner nonce = hex-decode(reverse(key[16:32]) + "68" + key[0:16])
//       truncated to 8 bytes; fields g,h,l,o,p,v,x,i,w that are hex
//       strings longer than 16 chars are ChaCha20(L3, nonce, 1)
//       decrypted and cut at the first NUL byte.
//   Single-letter keys map to readable names (KEY_MAP below).
//
// Method constants below are app-embedded format constants already
// present in this repo (SSCCUSTOM.py, SscPort.kt). They are NOT user
// credentials, accounts or tokens. Everything runs offline; no network,
// no key generation, no guessing between unrelated formats.
//
// Two behaviours of the server decoder are reproduced deliberately:
//  (1) two-layer files: _process_configs looks up "a" after the outer
//      mapping renamed it to "CONFIGS", so config items keep their
//      single-letter keys; (2) L3 fields of 16 hex chars or fewer
//      (<= 8 bytes of plaintext) are left encrypted by the length guard.
#include "spdecode_ssc.h"
#include <nlohmann/json.hpp>
#include <algorithm>
#include <array>
#include <cctype>
#include <cstdint>
#include <cstring>
#include <regex>
#include <stdexcept>
#include <string>
#include <vector>

namespace spdecode::offline {
namespace {
using Bytes = std::vector<unsigned char>;
using json = nlohmann::ordered_json;
struct SscFailure : std::runtime_error { using std::runtime_error::runtime_error; };
constexpr size_t kMaxInput = 1u * 1024u * 1024u;
constexpr size_t kMaxClear = 4u * 1024u * 1024u;

void ensure(bool ok, const char* code) {
    if (!ok) throw SscFailure(code);
}

// --- ChaCha20, original DJB variant (64-bit nonce, 64-bit counter) ---
uint32_t rotl32(uint32_t x, int bits) { return (x << bits) | (x >> (32 - bits)); }
void quarter(std::array<uint32_t, 16>& s, int a, int b, int c, int d) {
    s[a] += s[b]; s[d] = rotl32(s[d] ^ s[a], 16);
    s[c] += s[d]; s[b] = rotl32(s[b] ^ s[c], 12);
    s[a] += s[b]; s[d] = rotl32(s[d] ^ s[a], 8);
    s[c] += s[d]; s[b] = rotl32(s[b] ^ s[c], 7);
}
uint32_t readLE32(const unsigned char* p) {
    return static_cast<uint32_t>(p[0]) | (static_cast<uint32_t>(p[1]) << 8) |
           (static_cast<uint32_t>(p[2]) << 16) | (static_cast<uint32_t>(p[3]) << 24);
}
Bytes chacha20_64(const Bytes& key, const Bytes& nonce, const Bytes& input) {
    ensure(key.size() == 32 && nonce.size() == 8, "SSC_BAD_KEY");
    static constexpr std::array<uint32_t, 4> kConst = {0x61707865, 0x3320646e, 0x79622d32, 0x6b206574};
    Bytes out(input.size());
    uint64_t counter = 1;  // PyCryptodome seek(64): one 64-byte block.
    size_t pos = 0;
    while (pos < input.size()) {
        std::array<uint32_t, 16> state{};
        for (size_t i = 0; i < 4; i++) state[i] = kConst[i];
        for (size_t i = 0; i < 8; i++) state[4 + i] = readLE32(key.data() + i * 4);
        state[12] = static_cast<uint32_t>(counter & 0xffffffffu);
        state[13] = static_cast<uint32_t>(counter >> 32);
        state[14] = readLE32(nonce.data());
        state[15] = readLE32(nonce.data() + 4);
        std::array<uint32_t, 16> s = state;
        for (int i = 0; i < 10; i++) {
            quarter(s, 0, 4, 8, 12); quarter(s, 1, 5, 9, 13);
            quarter(s, 2, 6, 10, 14); quarter(s, 3, 7, 11, 15);
            quarter(s, 0, 5, 10, 15); quarter(s, 1, 6, 11, 12);
            quarter(s, 2, 7, 8, 13); quarter(s, 3, 4, 9, 14);
        }
        for (size_t i = 0; i < 16; i++) s[i] += state[i];
        const size_t count = std::min<size_t>(64, input.size() - pos);
        for (size_t j = 0; j < count; j++)
            out[pos + j] = static_cast<unsigned char>(
                input[pos + j] ^ ((s[j / 4] >> ((j % 4) * 8)) & 0xff));
        pos += count;
        counter++;
    }
    return out;
}

int hexVal(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}
bool fromHex(const std::string& text, Bytes& out) {
    if (text.size() % 2 != 0) return false;
    out.clear();
    out.reserve(text.size() / 2);
    for (size_t i = 0; i < text.size(); i += 2) {
        const int hi = hexVal(text[i]);
        const int lo = hexVal(text[i + 1]);
        if (hi < 0 || lo < 0) return false;
        out.push_back(static_cast<unsigned char>((hi << 4) | lo));
    }
    return true;
}
// Drop bytes that are not valid UTF-8 (mirrors errors="ignore").
std::string dropInvalidUtf8(const std::string& in) {
    std::string out;
    out.reserve(in.size());
    size_t i = 0;
    while (i < in.size()) {
        const unsigned char c = static_cast<unsigned char>(in[i]);
        size_t len = 0;
        uint32_t cp = 0;
        if (c < 0x80) { len = 1; cp = c; }
        else if ((c & 0xE0) == 0xC0) { len = 2; cp = c & 0x1F; }
        else if ((c & 0xF0) == 0xE0) { len = 3; cp = c & 0x0F; }
        else if ((c & 0xF8) == 0xF0) { len = 4; cp = c & 0x07; }
        else { i++; continue; }
        if (i + len > in.size()) break;
        bool ok = len > 1;
        for (size_t k = 1; k < len; k++) {
            const unsigned char cc = static_cast<unsigned char>(in[i + k]);
            if ((cc & 0xC0) != 0x80) { ok = false; break; }
            cp = (cp << 6) | (cc & 0x3F);
        }
        if (ok && ((len == 2 && cp >= 0x80) || (len == 3 && cp >= 0x800) ||
                   (len == 4 && cp >= 0x10000 && cp <= 0x10FFFF))) {
            out.append(in, i, len);
            i += len;
        } else if (len == 1) {
            out.push_back(in[i]);
            i++;
        } else {
            i++;
        }
    }
    return out;
}

std::string cstring(const Bytes& data) {
    size_t end = 0;
    while (end < data.size() && data[end] != 0) end++;
    return dropInvalidUtf8(std::string(
        reinterpret_cast<const char*>(data.data()), end));
}

// Mirror of SSCCUSTOM._clean_json: cut at first NUL, take { ... },
// parse; on trailing extra data, retry truncated at the error offset.
bool cleanJson(const Bytes& data, json& out) {
    if (data.empty()) return false;
    std::string text = cstring(data);
    const size_t start = text.find('{');
    const size_t end = text.rfind('}');
    if (start == std::string::npos || end == std::string::npos || end < start)
        return false;
    std::string candidate = text.substr(start, end - start + 1);
    try {
        out = json::parse(candidate);
        return true;
    } catch (const json::parse_error& e) {
        if (e.byte > 0 && e.byte <= candidate.size()) {
            try {
                out = json::parse(candidate.substr(0, static_cast<size_t>(e.byte)));
                return true;
            } catch (const std::exception&) {
                return false;
            }
        }
        return false;
    } catch (const std::exception&) {
        return false;
    }
}

const std::array<std::pair<const char*, const char*>, 25>& keyMap() {
    static const std::array<std::pair<const char*, const char*>, 25> kMap = {{
        {"a", "CONFIGS"}, {"b", "NOTE"}, {"c", "EXPIRY DATE"},
        {"e", "CONFIGNAME"}, {"f", "PAYLOAD ENABLED"}, {"g", "PAYLOAD"},
        {"h", "PROXY"}, {"i", "PROXY PORT"}, {"j", "TYPE"},
        {"k", "PROXY ENABLED"}, {"l", "ADDRESS"}, {"m", "PORT"},
        {"n", "IS PREMIUM"}, {"o", "USERNAME"}, {"p", "PASSWORD"},
        {"q", "TIMEOUT"}, {"r", "PROTOCOL"}, {"s", "VERSION"},
        {"t", "ENCRYPTION"}, {"u", "COMPRESSIONLEVEL"}, {"v", "DNS"},
        {"w", "NSSERVER"}, {"x", "PUBKEY"}, {"y", "ISDEFAULT"},
        {"z", "LOCALPORT"},
    }};
    return kMap;
}
std::string mappedKey(const std::string& key) {
    for (const auto& pair : keyMap())
        if (key == pair.first) return pair.second;
    return key;
}
bool isEncryptedField(const std::string& key) {
    static constexpr std::array<const char*, 9> kFields = {
        "g", "h", "l", "o", "p", "v", "x", "i", "w"};
    for (const char* f : kFields)
        if (key == f) return true;
    return false;
}
bool isAddressField(const std::string& name) {
    return name == "ADDRESS" || name == "DNS" || name == "H" ||
           name == "NSSERVER";
}
bool isFilteredField(const std::string& key) {
    return key == "l" || key == "v" || key == "w" || key == "h";
}

std::string stripControl(const std::string& in) {
    std::string out;
    for (char c : in)
        if (static_cast<unsigned char>(c) >= 32) out.push_back(c);
    return out;
}
std::string trimSpace(const std::string& in) {
    size_t b = 0;
    while (b < in.size() && std::isspace(static_cast<unsigned char>(in[b]))) b++;
    size_t e = in.size();
    while (e > b && std::isspace(static_cast<unsigned char>(in[e - 1]))) e--;
    return in.substr(b, e - b);
}
bool allAlnumAscii(const std::string& in) {
    if (in.empty()) return false;
    for (char c : in)
        if (!std::isalnum(static_cast<unsigned char>(c))) return false;
    return true;
}

// Mirror of SSCCUSTOM._sanitize_field (mapped key name as `key`).
json sanitizeField(const std::string& key, const json& value) {
    if (!value.is_string()) return value;
    std::string text = stripControl(value.get<std::string>());
    if (isAddressField(key)) {
        static const std::regex kIp(R"((?:\d{1,3}\.){3}\d{1,3}(?::\d+)?)");
        std::smatch m;
        if (std::regex_search(text, m, kIp)) return m.str(0);
        std::string out;
        for (char c : text)
            if (std::isalnum(static_cast<unsigned char>(c)) || c == '.' ||
                c == '-' || c == '_')
                out.push_back(c);
        return out;
    }
    if (key == "USERNAME" || key == "PASSWORD") {
        if (allAlnumAscii(text)) return text;
        static const std::regex kPrefix(R"(^[a-zA-Z0-9!@#$%^&*()._-]+)");
        std::smatch m;
        if (std::regex_search(text, m, kPrefix)) return m.str(0);
        return text;
    }
    if (key == "PAYLOAD") {
        if (text.find("[crlf]") != std::string::npos) {
            const size_t nul = text.find('\0');
            return nul == std::string::npos ? text : text.substr(0, nul);
        }
        return trimSpace(text);
    }
    return trimSpace(text);
}

bool deriveInnerNonce(const std::string& userKey, Bytes& nonce) {
    if (userKey.size() != 32) return false;
    for (char c : userKey)
        if (hexVal(c) < 0) return false;
    std::string built = userKey.substr(16, 16);
    std::reverse(built.begin(), built.end());
    built += "68";
    built += userKey.substr(0, 16);
    Bytes raw;
    if (!fromHex(built, raw) || raw.size() < 8) return false;
    nonce.assign(raw.begin(), raw.begin() + 8);
    return true;
}

// Mirror of SSCCUSTOM._process_configs. NOTE: it looks up "a" only, so
// for two-layer targets (already renamed to "CONFIGS") the configs are
// left untouched, exactly like the server decoder.
void processConfigs(json& obj, const Bytes& l3Key) {
    if (!obj.is_object() || !obj.contains("a") || !obj["a"].is_array()) return;
    json processed = json::array();
    for (auto& item : obj["a"]) {
        if (!item.is_object()) {
            processed.push_back(item);
            continue;
        }
        if (item.contains("b") && item["b"].is_string()) {
            Bytes nonce;
            if (deriveInnerNonce(item["b"].get<std::string>(), nonce)) {
                for (auto it = item.begin(); it != item.end(); ++it) {
                    const std::string field = it.key();
                    if (!isEncryptedField(field) || !it.value().is_string())
                        continue;
                    const std::string enc = it.value().get<std::string>();
                    if (enc.size() <= 16) continue;  // server length guard
                    Bytes cipher;
                    if (!fromHex(enc, cipher)) continue;
                    const Bytes plain = chacha20_64(l3Key, nonce, cipher);
                    std::string text = cstring(plain);
                    if (isFilteredField(field)) {
                        std::string filtered;
                        for (char c : text)
                            if (std::isalnum(static_cast<unsigned char>(c)) ||
                                c == '.' || c == '-' || c == ':' || c == '_')
                                filtered.push_back(c);
                        text = filtered;
                    }
                    it.value() = text;
                }
            }
        }
        json mapped = json::object();
        for (auto it = item.begin(); it != item.end(); ++it) {
            const std::string name = mappedKey(it.key());
            json value = sanitizeField(name, it.value());
            if (value.is_string() && value.get<std::string>().empty() &&
                isEncryptedField(it.key()))
                continue;
            mapped[name] = value;
        }
        processed.push_back(mapped);
    }
    obj["a"] = processed;
}

Bytes keyFromHex(const char* hex) {
    Bytes out;
    if (!fromHex(hex, out)) throw SscFailure("SSC_BAD_KEY");
    return out;
}

}  // namespace

std::string decodeSsc(const std::vector<unsigned char>& raw) {
    ensure(!raw.empty() && raw.size() <= kMaxInput, "SSC_INVALID_INPUT");
    const Bytes l1Key = keyFromHex(
        "c8a6a8ea102d5a0baf8fdb1b39cd615c0d07c1edcbde4e82cfdd309bc4587f6b");
    const Bytes l2Key = keyFromHex(
        "7f9db48ffde449ad19f9ed44b8b27eee334ab4a85b972dca8ff20e4e8ed44e4e");
    const Bytes l3Key = keyFromHex(
        "d39394517a48971f6e8555e994bee5bd835e5ab2f85fbd76bbd99800f32b967e");
    // Fixed nonce: little-endian uint64 0xf7479d9f87f3d074.
    const Bytes fixedNonce = {0x74, 0xd0, 0xf3, 0x87, 0x9f, 0x9d, 0x47, 0xf7};

    std::string content(reinterpret_cast<const char*>(raw.data()), raw.size());
    // UTF-8 BOM, as in decode('utf-8-sig').
    if (content.size() >= 3 && static_cast<unsigned char>(content[0]) == 0xEF &&
        static_cast<unsigned char>(content[1]) == 0xBB &&
        static_cast<unsigned char>(content[2]) == 0xBF)
        content.erase(0, 3);
    content = trimSpace(dropInvalidUtf8(content));
    if (content.rfind("ssc://", 0) == 0) {
        content = content.substr(6);
        std::reverse(content.begin(), content.end());
    }
    std::string cipherHex;
    for (char c : content)
        if (!std::isspace(static_cast<unsigned char>(c))) cipherHex.push_back(c);
    ensure(cipherHex.size() % 2 == 0, "SSC_INVALID_HEX");
    Bytes cipher;
    ensure(fromHex(cipherHex, cipher), "SSC_INVALID_HEX");
    ensure(cipher.size() <= kMaxClear, "SSC_INVALID_INPUT");
    const Bytes l1Data = chacha20_64(l1Key, fixedNonce, cipher);
    json l1;
    ensure(cleanJson(l1Data, l1), "SSC_INVALID_L1");

    json target;
    bool haveTarget = false;
    if (l1.contains("c") && l1.contains("a") && l1["a"].is_string()) {
        const std::string nonceHex = l1["a"].get<std::string>().substr(0, 16);
        Bytes nonce;
        ensure(fromHex(nonceHex, nonce) && nonce.size() == 8,
               "SSC_INVALID_L2_NONCE");
        Bytes l2Cipher;
        ensure(l1["c"].is_string() && fromHex(l1["c"].get<std::string>(), l2Cipher),
               "SSC_INVALID_L2");
        const Bytes l2Data = chacha20_64(l2Key, nonce, l2Cipher);
        json l2;
        if (cleanJson(l2Data, l2)) {
            json mapped = json::object();
            for (auto it = l2.begin(); it != l2.end(); ++it) {
                const std::string name = mappedKey(it.key());
                mapped[name] = (it.key() == "a")
                    ? it.value()
                    : sanitizeField(name, it.value());
            }
            target = mapped;
            haveTarget = true;
        }
    } else if (l1.contains("a") && l1["a"].is_array()) {
        target = l1;
        haveTarget = true;
    }
    ensure(haveTarget, "SSC_UNSUPPORTED_LAYER");

    processConfigs(target, l3Key);
    json finalObj = json::object();
    for (auto it = target.begin(); it != target.end(); ++it) {
        const std::string name = mappedKey(it.key());
        const bool keepList = (it.key() == "a" || it.key() == "CONFIGS") &&
                              it.value().is_array();
        finalObj[name] = keepList ? it.value()
                                  : sanitizeField(name, it.value());
    }
    return finalObj.dump(2, ' ', false, json::error_handler_t::strict) + "\n";
}

}  // namespace spdecode::offline

// TLS Tunnel (com.tlsvpn.tlstunnel, 8.5.0 / versionCode 516) - offline decoder.
//
// File format (.tls) and text format (tls://), per decoders/Python/TLS.py
// (method derived from APK 8.5.0, Ldd.o([B)[B):
//   1. strip an optional "tls://" prefix and any ":..." suffix;
//   2. reverse the outer Base64 string and Base64-decode it;
//   3. container = 12 bytes + C1 + IV1(18) + C2 + IV2(18) + 84 bytes,
//      with C1/C2 of (near-)equal length; reverse each fragment;
//   4. AES-256-GCM, nonce = IV1+IV2 (36 bytes), tag = last 16 bytes of
//      C1+C2; try the six known configuration-key profiles in order.
//      Only a verified GCM tag yields plaintext.
//   5. plaintext is a ":"-delimited field list; inner Base64 fields are
//      decoded; profile 6 (the historic single key) keeps the legacy DNS
//      field names, profiles 1-5 keep every field positionally in _tls.
//
// Method constants below are app-embedded format constants already present
// in this repo (decoders/Python/TLS.py CONFIG_KEYS, and the same six
// profiles in the online Kotlin reference TlsReferencePort.kt). They are
// NOT user credentials, accounts or tokens. Everything runs offline: no
// network, no server key, no Keystore, no live capture. The keys are
// fixed per app version; a future app release could rotate them, in which
// case files sealed with a new profile fail cleanly as TLS_AUTH_FAILED.
#include "spdecode_tls_tunnel.h"
#include <mbedtls/base64.h>
#include <mbedtls/gcm.h>
#include <algorithm>
#include <array>
#include <cctype>
#include <cstdint>
#include <cstring>
#include <stdexcept>
#include <string>
#include <vector>
#include <nlohmann/json.hpp>

namespace spdecode::offline {
namespace {
using Bytes = std::vector<unsigned char>;
using json = nlohmann::json;
struct TlsFailure : std::runtime_error { using std::runtime_error::runtime_error; };
constexpr size_t kMaxInput = 4u * 1024u * 1024u;
constexpr size_t kMaxClear = 1u * 1024u * 1024u;
constexpr size_t kTagLen = 16;

// Six AES-256 configuration-key profiles, in the exact order tried by
// decoders/Python/TLS.py CONFIG_KEYS (profile 6 is the historic AES_KEY).
constexpr std::array<const char*, 6> kConfigKeysHex = {
    "2474763534327665643235345671c38b72775742627236c2b324254856232433",
    "33cf82ceb7cf84e1baa135566ec6b0686e33d8b661d0bed0bdd0b12578745630",
    "23e4bc9acf82ceb7cf84e1baa135676ec6b0686e3332d8b661d0bed0bdd0b125",
    "23e4bc9ae685a246e1baa14235676ec6b0686e3332d8b661d0bed0bdd0b12534",
    "234673486ee1baa14246355c3332d8b6612534407c666433653247462847c38b",
    "6b303068c2acc2b9c2b221352473c2b0c2b725c2a824614b674433c2b0467856",
};
// Indices of the ":"-delimited fields whose values are inner Base64.
constexpr std::array<size_t, 12> kB64Fields = {4, 5, 6, 7, 9, 12, 14, 16, 18, 19, 24, 27};

void require(bool ok, const char* reason) {
    if (!ok) throw TlsFailure(reason);
}

bool isB64Field(size_t index) {
    return std::find(kB64Fields.begin(), kB64Fields.end(), index) != kB64Fields.end();
}

int hexVal(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

Bytes hexDecode(const char* hex, size_t hexLen) {
    require(hexLen % 2 == 0, "TLS_BAD_KEY");
    Bytes out(hexLen / 2);
    for (size_t i = 0; i < out.size(); i++) {
        const int hi = hexVal(hex[2 * i]);
        const int lo = hexVal(hex[2 * i + 1]);
        require(hi >= 0 && lo >= 0, "TLS_BAD_KEY");
        out[i] = static_cast<unsigned char>((hi << 4) | lo);
    }
    return out;
}

bool validUtf8(const std::string& text) {
    size_t i = 0;
    while (i < text.size()) {
        const auto c = static_cast<unsigned char>(text[i]);
        size_t extra = 0;
        uint32_t cp = 0;
        if (c < 0x80) { i++; continue; }
        if ((c & 0xE0) == 0xC0) { extra = 1; cp = c & 0x1F; if (cp < 2) return false; }
        else if ((c & 0xF0) == 0xE0) { extra = 2; cp = c & 0x0F; }
        else if ((c & 0xF8) == 0xF0) { extra = 3; cp = c & 0x07; if (cp > 4) return false; }
        else return false;
        if (i + extra >= text.size()) return false;
        for (size_t k = 1; k <= extra; k++) {
            const auto cc = static_cast<unsigned char>(text[i + k]);
            if ((cc & 0xC0) != 0x80) return false;
            cp = (cp << 6) | (cc & 0x3F);
        }
        if (extra == 2 && cp < 0x800) return false;
        if (extra == 3 && (cp < 0x10000 || cp > 0x10FFFF)) return false;
        if (cp >= 0xD800 && cp <= 0xDFFF) return false;
        i += extra + 1;
    }
    return true;
}

std::string trimAscii(const std::string& value) {
    const auto first = value.find_first_not_of(" \r\n\t");
    if (first == std::string::npos) return {};
    const auto last = value.find_last_not_of(" \r\n\t");
    return value.substr(first, last - first + 1);
}

// Strict Base64 decode (alphabet + '=' only as trailing padding), mirroring
// Python base64.b64decode(..., validate=True). Returns false on bad input.
bool b64DecodeStrict(const std::string& encoded, Bytes& out) {
    if (encoded.empty() || encoded.size() % 4 != 0) return false;
    size_t pad = 0;
    while (pad < encoded.size() && encoded[encoded.size() - 1 - pad] == '=') pad++;
    if (pad > 2) return false;
    for (size_t i = 0; i < encoded.size(); i++) {
        const char c = encoded[i];
        if (c == '=') {
            if (i < encoded.size() - pad) return false;
        } else if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                     (c >= '0' && c <= '9') || c == '+' || c == '/')) {
            return false;
        }
    }
    out.assign(encoded.size() * 3 / 4 + 4, 0);
    size_t size = 0;
    if (mbedtls_base64_decode(out.data(), out.size(), &size,
            reinterpret_cast<const unsigned char*>(encoded.data()),
            encoded.size()) != 0) {
        return false;
    }
    out.resize(size);
    return true;
}

// Python decode_internal_b64: pad, strict-decode, UTF-8 decode; on any
// failure return the original string untouched.
std::string decodeInnerB64(const std::string& value) {
    if (value.empty()) return {};
    std::string padded = value;
    while (padded.size() % 4 != 0) padded.push_back('=');
    Bytes bytes;
    if (!b64DecodeStrict(padded, bytes)) return value;
    std::string text(bytes.begin(), bytes.end());
    if (!validUtf8(text)) return value;
    return text;
}

long long safeInt(const std::string& rawValue) {
    // Python int() accepts surrounding whitespace and a sign.
    const std::string value = trimAscii(rawValue);
    if (value.empty()) return 0;
    size_t i = 0;
    bool neg = false;
    if (value[i] == '+' || value[i] == '-') { neg = value[i] == '-'; i++; }
    if (i >= value.size()) return 0;
    long long result = 0;
    for (; i < value.size(); i++) {
        const char c = value[i];
        if (c < '0' || c > '9') return 0;
        if (result > (9223372036854775807LL - (c - '0')) / 10) return 0;
        result = result * 10 + (c - '0');
    }
    return neg ? -result : result;
}

bool boolValue(const std::string& value) {
    std::string lower;
    lower.reserve(value.size());
    for (char c : value) {
        lower.push_back(static_cast<char>(
            std::tolower(static_cast<unsigned char>(c))));
    }
    return lower == "true";
}

// Python mensagem replacements: U+047A (D1 BA) -> '\n', U+047B (D1 BB) -> '\r'.
std::string fixMensagem(const std::string& value) {
    std::string out;
    out.reserve(value.size());
    for (size_t i = 0; i < value.size(); i++) {
        if (i + 1 < value.size() &&
            static_cast<unsigned char>(value[i]) == 0xD1 &&
            static_cast<unsigned char>(value[i + 1]) == 0xBA) {
            out.push_back('\n');
            i++;
        } else if (i + 1 < value.size() &&
                   static_cast<unsigned char>(value[i]) == 0xD1 &&
                   static_cast<unsigned char>(value[i + 1]) == 0xBB) {
            out.push_back('\r');
            i++;
        } else {
            out.push_back(value[i]);
        }
    }
    return out;
}

Bytes reversed(const Bytes& data, size_t begin, size_t end) {
    Bytes out(data.begin() + static_cast<long>(begin),
              data.begin() + static_cast<long>(end));
    std::reverse(out.begin(), out.end());
    return out;
}
} // namespace

std::string decodeTls(const std::vector<unsigned char>& raw) {
    require(!raw.empty() && raw.size() <= kMaxInput, "TLS_EMPTY_INPUT");
    std::string text(raw.begin(), raw.end());
    // Strip a UTF-8 BOM exactly like Python's utf-8-sig file read.
    if (text.size() >= 3 &&
        static_cast<unsigned char>(text[0]) == 0xEF &&
        static_cast<unsigned char>(text[1]) == 0xBB &&
        static_cast<unsigned char>(text[2]) == 0xBF) {
        text.erase(0, 3);
    }
    text = trimAscii(text);
    if (text.rfind("tls://", 0) == 0) text.erase(0, 6);
    const auto colon = text.find(':');
    if (colon != std::string::npos) text.erase(colon);
    std::string token;
    token.reserve(text.size());
    for (char c : text) {
        if (c != ' ' && c != '\r' && c != '\n' && c != '\t') token.push_back(c);
    }
    require(!token.empty(), "TLS_EMPTY_INPUT");

    std::string reversedB64(token.rbegin(), token.rend());
    while (reversedB64.size() % 4 != 0) reversedB64.push_back('=');
    Bytes container;
    require(b64DecodeStrict(reversedB64, container), "TLS_INVALID_BASE64");
    require(container.size() >= 148, "TLS_CONTAINER_TOO_SHORT");
    const size_t len = container.size();
    // half_math = ((len - 96) - 36) // 2, exactly as in TLS.py.
    const size_t half = (len - 132) / 2;
    require(len - 102 >= 30 + half, "TLS_INVALID_LENGTH");
    const Bytes c1 = reversed(container, 12, 12 + half);
    const Bytes iv1 = reversed(container, 12 + half, 30 + half);
    const Bytes c2 = reversed(container, 30 + half, len - 102);
    const Bytes iv2 = reversed(container, len - 102, len - 84);
    require(iv1.size() == 18 && iv2.size() == 18, "TLS_INVALID_LENGTH");

    Bytes stitched = c1;
    stitched.insert(stitched.end(), c2.begin(), c2.end());
    require(stitched.size() >= kTagLen, "TLS_INVALID_LENGTH");
    Bytes nonce = iv1;
    nonce.insert(nonce.end(), iv2.begin(), iv2.end());
    const size_t ctLen = stitched.size() - kTagLen;
    Bytes clear(ctLen);
    int profile = 0;
    for (size_t index = 0; index < kConfigKeysHex.size(); index++) {
        const Bytes key = hexDecode(kConfigKeysHex[index], 64);
        require(key.size() == 32, "TLS_BAD_KEY");
        mbedtls_gcm_context ctx;
        mbedtls_gcm_init(&ctx);
        int rc = mbedtls_gcm_setkey(&ctx, MBEDTLS_CIPHER_ID_AES,
                                    key.data(), 256);
        if (rc == 0) {
            rc = mbedtls_gcm_auth_decrypt(&ctx, ctLen, nonce.data(), nonce.size(),
                    nullptr, 0, stitched.data() + ctLen, kTagLen,
                    stitched.data(), clear.data());
        }
        mbedtls_gcm_free(&ctx);
        if (rc == 0) { profile = static_cast<int>(index) + 1; break; }
        std::fill(clear.begin(), clear.end(), 0);
    }
    require(profile != 0, "TLS_AUTH_FAILED");
    require(clear.size() <= kMaxClear, "TLS_OUTPUT_TOO_LARGE");
    const std::string plain(clear.begin(), clear.end());
    std::fill(clear.begin(), clear.end(), 0);
    require(validUtf8(plain), "TLS_INVALID_UTF8");

    std::vector<std::string> parts;
    size_t start = 0;
    while (true) {
        const auto pos = plain.find(':', start);
        if (pos == std::string::npos) { parts.push_back(plain.substr(start)); break; }
        parts.push_back(plain.substr(start, pos - start));
        start = pos + 1;
    }
    const auto part = [&parts](size_t index) -> std::string {
        return index < parts.size() ? parts[index] : std::string();
    };
    const auto decoded = [&part](size_t index) -> std::string {
        return decodeInnerB64(part(index));
    };

    // Mirror Python _render_config(decrypt_tls_payload(...)): named fields
    // in order, empty strings dropped, _tls metadata for profiles 1-5.
    json config = json::object();
    auto keepStr = [&config](const char* name, const std::string& value) {
        if (!value.empty()) config[name] = value;
    };
    config["tlsvpnVersion"] = safeInt(part(0));
    config["server"] = safeInt(part(1));
    config["port"] = safeInt(part(2));
    config["pserver"] = boolValue(part(3));
    keepStr("sshuser", decoded(4));
    keepStr("sshpass", decoded(5));
    keepStr("sshhost", decoded(6));
    keepStr("server_port", decoded(7));
    keepStr("sshport", decoded(9));
    config["metodo"] = safeInt(part(10));
    config["upayload"] = boolValue(part(11));
    keepStr("payload", decoded(12));
    config["usnihost"] = boolValue(part(13));
    keepStr("snihost", decoded(14));
    config["upayloadat"] = boolValue(part(15));
    keepStr("payloadat", decoded(16));
    config["uproxy"] = boolValue(part(17));
    keepStr("prxhost", decoded(18));
    keepStr("prxport", decoded(19));
    if (profile == 6) {
        config["legacy_dns_mode"] = safeInt(part(20));
        keepStr("dnsP", decoded(21));
        keepStr("dns_port", decoded(22));
        keepStr("nameserver", decoded(23));
        keepStr("public_key", decoded(24));
    }
    config["bloqmc"] = boolValue(part(25));
    keepStr("mensagem", fixMensagem(decoded(27)));
    if (profile != 6) {
        json fields = json::array();
        for (size_t i = 0; i < parts.size(); i++) {
            json field;
            field["index"] = i;
            field["raw"] = parts[i];
            field["value"] = isB64Field(i) ? decoded(i) : parts[i];
            fields.push_back(field);
        }
        json meta;
        meta["authenticated"] = true;
        meta["key_profile"] = profile;
        meta["field_count"] = parts.size();
        meta["fields"] = fields;
        config["_tls"] = meta;
    }
    return config.dump(2);
}
} // namespace spdecode::offline

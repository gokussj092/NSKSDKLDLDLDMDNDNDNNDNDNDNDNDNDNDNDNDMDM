// ZIVPN Tunnel (com.zi.zivpn, 2.2.5 / versionCode 184) - offline decoder.
//
// File format (.ziv), per decoders/Python/apps/ZIVPN/ZIVPN_archivos.py:
//   file = Base64(salt) "." Base64(iv) "." Base64(ct+tag)
//   salt 32 B, iv 12 B; key = PBKDF2-HMAC-SHA256(password, salt, 1000, 16 B);
//   AES-128-GCM, no AAD; inner layer DES/ECB/PKCS5Padding; interior is a
//   java.util.Properties XML document ("Configuration File").
// The app's own export applies the LF1 (AES-GCM) layer only, while its
// import expects LF1 -> DES -> XML, so decode tries DES first and falls
// back to the raw inner bytes (export-style) when DES does not yield XML.
// Text format (zivpn://), per decoders/Python/text_legacy_protocols.py:
//   "zivpn://" + Base64(AES-256-CBC(key=SHA256(text password), IV=0,
//   PKCS7) of the Properties XML (or JSON) plaintext).
//
// Method constants below are app-embedded format constants already present
// in this repo (decoders/Python/ziv.py, embedded_kotlin_profiles.json and
// the online reference). They are NOT user credentials, accounts or tokens.
// Everything runs offline; no network, no key generation, no guessing
// between unrelated formats: only the two known .ziv passwords are tried,
// and GCM authentication decides.
#include "spdecode_zivpn.h"
#include <mbedtls/aes.h>
#include <mbedtls/base64.h>
#include <mbedtls/des.h>
#include <mbedtls/gcm.h>
#include <mbedtls/md.h>
#include <mbedtls/pkcs5.h>
#include <mbedtls/sha256.h>
#include <mbedtls/version.h>
#include <nlohmann/json.hpp>
#include <algorithm>
#include <array>
#include <cctype>
#include <cstdint>
#include <cstring>
#include <stdexcept>
#include <string>
#include <vector>

namespace spdecode::offline {
namespace {
using Bytes = std::vector<unsigned char>;
using json = nlohmann::json;
struct ZivFailure : std::runtime_error { using std::runtime_error::runtime_error; };
constexpr size_t kMaxInput = 4u * 1024u * 1024u;
constexpr size_t kMaxClear = 4u * 1024u * 1024u;
// Current fixed LF1 password first, then the legacy password kept by
// decoders/Python/ziv.py for older files. GCM authentication decides.
constexpr std::array<const char*, 2> kLf1Passwords = {
    "SecurePart1SecurePart2SecurePart3SecurePart4SecurePart5",
    "fubvx788b46v",
};
// DESKeySpec value from the reference; DES uses its first 8 bytes.
constexpr char kDesKeySpec[] = "#ipt!2022/H";
// Text-link password, base64-encoded exactly as in text_legacy_protocols.py.
constexpr char kTextPasswordB64[] = "dTlxdXdscWs4ODFkaTFneGpuMWF1YnkzZmFmdm9tOXQ=";
constexpr size_t kSaltLen = 32;
constexpr size_t kIvLen = 12;
constexpr size_t kTagLen = 16;
constexpr unsigned kPbkdf2Iters = 1000;
constexpr size_t kAes128KeyLen = 16;

void require(bool ok, const char* reason) {
    if (!ok) throw ZivFailure(reason);
}

std::string trim(const std::string& value) {
    const auto first = value.find_first_not_of(" \r\n\t");
    if (first == std::string::npos) return {};
    const auto last = value.find_last_not_of(" \r\n\t");
    return value.substr(first, last - first + 1);
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

Bytes b64decode(const std::string& part) {
    std::string encoded;
    encoded.reserve(part.size() + 4);
    for (char ch : part) {
        const auto c = static_cast<unsigned char>(ch);
        if (c == ' ' || c == '\r' || c == '\n' || c == '\t') continue;
        if (c == '-') encoded.push_back('+');
        else if (c == '_') encoded.push_back('/');
        else if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                 (c >= '0' && c <= '9') || c == '+' || c == '/' || c == '=') {
            encoded.push_back(ch);
        } else {
            throw ZivFailure("ZIV_INVALID_BASE64");
        }
    }
    require(!encoded.empty() && encoded.size() <= kMaxInput * 2, "ZIV_INVALID_BASE64");
    while (encoded.size() % 4 != 0) encoded.push_back('=');
    Bytes out(encoded.size() * 3 / 4 + 4);
    size_t size = 0;
    require(mbedtls_base64_decode(out.data(), out.size(), &size,
            reinterpret_cast<const unsigned char*>(encoded.data()),
            encoded.size()) == 0, "ZIV_INVALID_BASE64");
    out.resize(size);
    require(!out.empty() && out.size() <= kMaxClear, "ZIV_INVALID_BASE64");
    return out;
}

std::array<unsigned char, 32> sha256(const unsigned char* data, size_t size) {
    std::array<unsigned char, 32> out{};
    // 2.28 returns void; 3.x returns int.
#if MBEDTLS_VERSION_NUMBER >= 0x03000000
    require(mbedtls_sha256(data, size, out.data(), 0) == 0, "ZIV_SHA256_FAILED");
#else
    mbedtls_sha256(data, size, out.data(), 0);
#endif
    return out;
}

Bytes pbkdf2Sha256(const std::string& password, const Bytes& salt) {
    Bytes key(kAes128KeyLen);
    // Mbed TLS 3.x (the Android build, 3.6.7) uses the _ext entry point;
    // the 2.28 line used by the CI host-parity build only has the
    // md_context entry point, which is deprecated in 3.x and would fail
    // the Android -Werror build. Both compute PBKDF2-HMAC-SHA256.
#if MBEDTLS_VERSION_NUMBER >= 0x03000000
    require(mbedtls_pkcs5_pbkdf2_hmac_ext(MBEDTLS_MD_SHA256,
            reinterpret_cast<const unsigned char*>(password.data()),
            password.size(), salt.data(), salt.size(), kPbkdf2Iters,
            static_cast<uint32_t>(key.size()), key.data()) == 0,
            "ZIV_PBKDF2_FAILED");
#else
    mbedtls_md_context_t mdCtx;
    mbedtls_md_init(&mdCtx);
    int rc = mbedtls_md_setup(&mdCtx,
            mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), 1);
    if (rc == 0) {
        rc = mbedtls_pkcs5_pbkdf2_hmac(&mdCtx,
                reinterpret_cast<const unsigned char*>(password.data()),
                password.size(), salt.data(), salt.size(), kPbkdf2Iters,
                static_cast<uint32_t>(key.size()), key.data());
    }
    mbedtls_md_free(&mdCtx);
    require(rc == 0, "ZIV_PBKDF2_FAILED");
#endif
    return key;
}

Bytes gcmDecrypt(const Bytes& key, const Bytes& iv, const Bytes& ctAndTag) {
    require(ctAndTag.size() > kTagLen, "ZIV_INVALID_ENVELOPE");
    const size_t ctLen = ctAndTag.size() - kTagLen;
    Bytes out(ctLen);
    mbedtls_gcm_context ctx;
    mbedtls_gcm_init(&ctx);
    int rc = mbedtls_gcm_setkey(&ctx, MBEDTLS_CIPHER_ID_AES, key.data(), 128);
    if (rc == 0) {
        rc = mbedtls_gcm_auth_decrypt(&ctx, ctLen, iv.data(), iv.size(),
                nullptr, 0, ctAndTag.data() + ctLen, kTagLen,
                ctAndTag.data(), out.data());
    }
    mbedtls_gcm_free(&ctx);
    require(rc == 0, "ZIV_AUTH_FAILED");
    return out;
}

// DES/ECB with PKCS5 unpadding; returns empty when the layer is absent
// (bad padding / wrong length) instead of throwing, so the caller can
// fall back to the export-style (LF1-only) inner bytes.
Bytes desEcbDecrypt(const Bytes& data) {
    if (data.empty() || data.size() % 8 != 0 || data.size() > kMaxClear) return {};
    mbedtls_des_context ctx;
    mbedtls_des_init(&ctx);
    std::array<unsigned char, 8> key{};
    std::memcpy(key.data(), kDesKeySpec, key.size());
    Bytes out(data.size());
    int rc = mbedtls_des_setkey_dec(&ctx, key.data());
    for (size_t n = 0; rc == 0 && n < data.size(); n += 8) {
        rc = mbedtls_des_crypt_ecb(&ctx, data.data() + n, out.data() + n);
    }
    mbedtls_des_free(&ctx);
    if (rc != 0) return {};
    const size_t pad = out.back();
    if (pad < 1 || pad > 8 || pad > out.size()) return {};
    unsigned char diff = 0;
    for (size_t i = 0; i < pad; i++) {
        diff |= static_cast<unsigned char>(out[out.size() - 1 - i] ^ pad);
    }
    if (diff != 0) return {};
    out.resize(out.size() - pad);
    return out;
}

std::string xmlUnescape(const std::string& value) {
    // Parses a numeric character reference "&#...;" (decimal or hex) at
    // value[pos] ('&' at pos) and returns its code point plus the ';'
    // position. Throws ZIV_INVALID_XML on any malformed reference.
    auto parseCharRef = [&value](size_t pos, unsigned long& cp, size_t& semiOut) {
        const size_t semi = value.find(';', pos);
        require(semi != std::string::npos && semi - pos <= 10, "ZIV_INVALID_XML");
        const std::string entity = value.substr(pos + 1, semi - pos - 1);
        require(entity.size() > 1 && entity[0] == '#', "ZIV_INVALID_XML");
        cp = 0;
        if (entity[1] == 'x' || entity[1] == 'X') {
            require(entity.size() > 2, "ZIV_INVALID_XML");
            for (size_t k = 2; k < entity.size(); k++) {
                const char c = entity[k];
                require((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') ||
                        (c >= 'A' && c <= 'F'), "ZIV_INVALID_XML");
                cp = cp * 16 + static_cast<unsigned long>(
                    c <= '9' ? c - '0' : (c <= 'F' ? c - 'A' + 10 : c - 'a' + 10));
                require(cp <= 0x10FFFF, "ZIV_INVALID_XML");
            }
        } else {
            for (size_t k = 1; k < entity.size(); k++) {
                require(entity[k] >= '0' && entity[k] <= '9', "ZIV_INVALID_XML");
                cp = cp * 10 + static_cast<unsigned long>(entity[k] - '0');
                require(cp <= 0x10FFFF, "ZIV_INVALID_XML");
            }
        }
        semiOut = semi;
    };

    std::string out;
    out.reserve(value.size());
    for (size_t i = 0; i < value.size(); i++) {
        if (value[i] != '&') { out.push_back(value[i]); continue; }
        unsigned long cp = 0;
        size_t semi = 0;
        if (i + 1 < value.size() && value[i + 1] == '#') {
            parseCharRef(i, cp, semi);
            if (cp >= 0xD800 && cp <= 0xDBFF) {
                // High surrogate: java.util.Properties writes astral
                // characters (e.g. emoji) as a pair of numeric references,
                // "&#55356;&#56808;" for U+1F608. A lone surrogate is not a
                // valid XML 1.0 character, so it still fails; a matched
                // pair combines into the single code point.
                const size_t next = semi + 1;
                require(next + 1 < value.size() && value[next] == '&' &&
                        value[next + 1] == '#', "ZIV_INVALID_XML");
                unsigned long lo = 0;
                size_t semi2 = 0;
                parseCharRef(next, lo, semi2);
                require(lo >= 0xDC00 && lo <= 0xDFFF, "ZIV_INVALID_XML");
                cp = 0x10000UL + ((cp - 0xD800) << 10) + (lo - 0xDC00);
                semi = semi2;
            } else {
                require(cp > 0 && !(cp >= 0xD800 && cp <= 0xDFFF), "ZIV_INVALID_XML");
            }
        } else {
            const size_t semiPos = value.find(';', i);
            require(semiPos != std::string::npos && semiPos - i <= 10, "ZIV_INVALID_XML");
            const std::string entity = value.substr(i + 1, semiPos - i - 1);
            if (entity == "amp") { out.push_back('&'); i = semiPos; continue; }
            if (entity == "lt") { out.push_back('<'); i = semiPos; continue; }
            if (entity == "gt") { out.push_back('>'); i = semiPos; continue; }
            if (entity == "quot") { out.push_back('"'); i = semiPos; continue; }
            if (entity == "apos") { out.push_back('\''); i = semiPos; continue; }
            throw ZivFailure("ZIV_INVALID_XML");
        }
        // Emit cp as UTF-8 (cp > 0, not a lone surrogate, <= 0x10FFFF).
        if (cp < 0x80) out.push_back(static_cast<char>(cp));
        else if (cp < 0x800) {
            out.push_back(static_cast<char>(0xC0 | (cp >> 6)));
            out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
        } else if (cp < 0x10000) {
            out.push_back(static_cast<char>(0xE0 | (cp >> 12)));
            out.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3F)));
            out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
        } else {
            out.push_back(static_cast<char>(0xF0 | (cp >> 18)));
            out.push_back(static_cast<char>(0x80 | ((cp >> 12) & 0x3F)));
            out.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3F)));
            out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
        }
        i = semi;
    }
    return out;
}

// Extracts <entry key="...">value</entry> / <entry key="..."/> pairs from a
// java.util.Properties XML document. Bare <entry> fragments (as used by the
// legacy zivpn:// text test) are accepted when requireRoot is false.
json parsePropertiesXml(const std::string& text, bool requireRoot) {
    require(validUtf8(text), "ZIV_INVALID_XML");
    if (requireRoot) require(text.find("<properties") != std::string::npos, "ZIV_INVALID_XML");
    json props = json::object();
    size_t pos = 0;
    while (true) {
        const size_t start = text.find("<entry", pos);
        if (start == std::string::npos) break;
        const size_t tagEnd = text.find('>', start);
        require(tagEnd != std::string::npos, "ZIV_INVALID_XML");
        const std::string tag = text.substr(start, tagEnd - start + 1);
        size_t keyPos = tag.find("key=\"");
        std::string quote = "\"";
        if (keyPos == std::string::npos) {
            keyPos = tag.find("key='");
            quote = "'";
        }
        require(keyPos != std::string::npos, "ZIV_INVALID_XML");
        const size_t keyStart = keyPos + 5;
        const size_t keyEnd = tag.find(quote, keyStart);
        require(keyEnd != std::string::npos, "ZIV_INVALID_XML");
        const std::string key = xmlUnescape(tag.substr(keyStart, keyEnd - keyStart));
        require(!key.empty(), "ZIV_INVALID_XML");
        if (tag.size() >= 2 && tag[tag.size() - 2] == '/') {
            props[key] = "";
            pos = tagEnd + 1;
            continue;
        }
        const size_t close = text.find("</entry>", tagEnd);
        require(close != std::string::npos, "ZIV_INVALID_XML");
        props[key] = xmlUnescape(text.substr(tagEnd + 1, close - tagEnd - 1));
        pos = close + 8;
    }
    require(!props.empty(), "ZIV_INVALID_XML");
    return props;
}

Bytes aes256CbcDecrypt(const Bytes& ciphertext, const Bytes& key) {
    require(ciphertext.size() % 16 == 0 && !ciphertext.empty(), "ZIV_INVALID_TEXT");
    require(key.size() == 32, "ZIV_INVALID_TEXT");
    Bytes out(ciphertext.size());
    mbedtls_aes_context ctx;
    mbedtls_aes_init(&ctx);
    int rc = mbedtls_aes_setkey_dec(&ctx, key.data(), 256);
    std::array<unsigned char, 16> iv{};
    if (rc == 0) {
        rc = mbedtls_aes_crypt_cbc(&ctx, MBEDTLS_AES_DECRYPT, ciphertext.size(),
                                   iv.data(), ciphertext.data(), out.data());
    }
    mbedtls_aes_free(&ctx);
    require(rc == 0, "ZIV_INVALID_TEXT");
    const size_t pad = out.back();
    require(pad >= 1 && pad <= 16 && pad <= out.size(), "ZIV_INVALID_PADDING");
    unsigned char diff = 0;
    for (size_t i = 0; i < pad; i++) {
        diff |= static_cast<unsigned char>(out[out.size() - 1 - i] ^ pad);
    }
    require(diff == 0, "ZIV_INVALID_PADDING");
    out.resize(out.size() - pad);
    return out;
}
}  // namespace

std::string decodeZiv(const std::vector<unsigned char>& raw) {
    require(!raw.empty() && raw.size() <= kMaxInput, "ZIV_INVALID_INPUT");
    const std::string text = trim(std::string(raw.begin(), raw.end()));
    require(!text.empty(), "ZIV_INVALID_INPUT");
    // Unencrypted Properties XML (same interior as the catalog XML form).
    if (text.rfind("<?xml", 0) == 0 || text.rfind("<properties", 0) == 0) {
        return parsePropertiesXml(text, true).dump();
    }
    size_t first = text.find('.');
    size_t second = text.find('.', first == std::string::npos ? 0 : first + 1);
    require(first != std::string::npos && second != std::string::npos &&
            text.find('.', second + 1) == std::string::npos, "ZIV_INVALID_ENVELOPE");
    const Bytes salt = b64decode(text.substr(0, first));
    const Bytes iv = b64decode(text.substr(first + 1, second - first - 1));
    const Bytes ctAndTag = b64decode(text.substr(second + 1));
    require(salt.size() == kSaltLen, "ZIV_INVALID_ENVELOPE");
    require(iv.size() == kIvLen, "ZIV_INVALID_ENVELOPE");
    require(ctAndTag.size() > kTagLen, "ZIV_INVALID_ENVELOPE");
    Bytes inner;
    bool opened = false;
    for (const char* password : kLf1Passwords) {
        const Bytes key = pbkdf2Sha256(password, salt);
        try {
            inner = gcmDecrypt(key, iv, ctAndTag);
            opened = true;
            break;
        } catch (const ZivFailure&) {
            continue;
        }
    }
    require(opened, "ZIV_AUTH_FAILED");
    // Legacy import format: DES layer present. Export-style files (LF1
    // only) fall through to the raw inner bytes. Either variant may be
    // tried: a DES-shaped payload that is not Properties XML falls back
    // to the raw bytes instead of failing outright.
    const Bytes desLayer = desEcbDecrypt(inner);
    if (!desLayer.empty()) {
        try {
            return parsePropertiesXml(
                std::string(desLayer.begin(), desLayer.end()), true).dump();
        } catch (const ZivFailure&) {
            // Not a legacy file after all; try the export-style bytes.
        }
    }
    return parsePropertiesXml(std::string(inner.begin(), inner.end()), true).dump();
}

std::string decodeZivpnText(const std::vector<unsigned char>& raw) {
    require(!raw.empty() && raw.size() <= kMaxInput, "ZIV_INVALID_TEXT");
    std::string text = trim(std::string(raw.begin(), raw.end()));
    require(!text.empty(), "ZIV_INVALID_TEXT");
    std::string lower = text;
    std::transform(lower.begin(), lower.end(), lower.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    if (lower.rfind("zivpn://", 0) == 0) text = trim(text.substr(8));
    require(!text.empty(), "ZIV_INVALID_TEXT");
    const Bytes ciphertext = b64decode(text);
    require(ciphertext.size() % 16 == 0, "ZIV_INVALID_TEXT");
    const Bytes passwordBytes = b64decode(kTextPasswordB64);
    const auto keyArr = sha256(passwordBytes.data(), passwordBytes.size());
    const Bytes key(keyArr.begin(), keyArr.end());
    const Bytes plain = aes256CbcDecrypt(ciphertext, key);
    require(!plain.empty() && plain.size() <= kMaxClear, "ZIV_INVALID_TEXT");
    const std::string clear(plain.begin(), plain.end());
    require(validUtf8(clear) && !trim(clear).empty(), "ZIV_INVALID_TEXT");
    try {
        const json parsed = json::parse(clear);
        if (parsed.is_object() || parsed.is_array()) return parsed.dump();
    } catch (const std::exception&) {
        // Not JSON: fall through to the Properties XML form.
    }
    try {
        return parsePropertiesXml(clear, false).dump();
    } catch (const ZivFailure&) {
        return json({{"decodedText", clear}}).dump();
    }
}
}  // namespace spdecode::offline

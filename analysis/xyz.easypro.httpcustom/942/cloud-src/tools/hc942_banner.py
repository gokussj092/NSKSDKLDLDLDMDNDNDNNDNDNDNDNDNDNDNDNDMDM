import hashlib
import hmac
import json
import struct
import re
from typing import Any, Dict, List, Optional, Tuple

try:
    from Crypto.Cipher import ChaCha20_Poly1305
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False

V4_PACKAGE = b"xyz.easypro.httpcustom"
V4_OUTER_SEED = b"hc-envelope-seal-v4 xyz.easypro.httpcustom"
V4_OUTER_SALT = b"hc-envelope-seal-salt-v4"
V4_OUTER_INFO = b"hc-envelope-seal-info-v4"
V4_OUTER_AAD = b"HCX4|xyz.easypro.httpcustom|1"
V4_CERT_DIGEST = bytes.fromhex(
    "95dd433d7e4a0be02d55cc62553edcfc8f077fe780be5a7da7f861c2558dc181"
)
V4_IPAD_STATE = [
    0x82515A9A, 0xF6EC05FC, 0xF650B6CD, 0x523F8CE6,
    0xEDF419EC, 0x1D6D6573, 0x66FF1B89, 0xF40A0181,
]
V4_OPAD_STATE = [
    0x82185B01, 0x35CB48BE, 0xDB6C3846, 0xBD714EC5,
    0x627728AF, 0xDBAAE4DB, 0x463FBF8D, 0x88A24381,
]
N15_IPAD_STATE = [
    0xAABD3A1E, 0x3D63A211, 0xE615B378, 0x46A07517,
    0x11F5CAB4, 0xA7AEF829, 0x83C7543B, 0x2D971AB7,
]
N15_OPAD_STATE = [
    0x423FCB79, 0xC4DD3DC8, 0x57D814AC, 0x1660ED59,
    0xDBB328B7, 0xCC389261, 0x06F1803E, 0xE3130C6B,
]
N19_IPAD_STATE = [
    0xBE68D8A0, 0x4972CC8B, 0xFB623F3A, 0x71B28162,
    0xFEFAE202, 0xB892B6D7, 0x61211CB5, 0x47B148AE,
]
N19_OPAD_STATE = [
    0x29EC5B88, 0xE7AACC30, 0xE7F995A0, 0xFE072DFB,
    0x1D8962B0, 0x035437DB, 0xBBA98361, 0x4B991E23,
]

V4_VERSION_LABEL_934 = "8.0.22 Patch 2 (934)"
V4_SHA256_K = [
    0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5, 0x3956C25B, 0x59F111F1, 0x923F82A4, 0xAB1C5ED5,
    0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3, 0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174,
    0xE49B69C1, 0xEFBE4786, 0x0FC19DC6, 0x240CA1CC, 0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA,
    0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7, 0xC6E00BF3, 0xD5A79147, 0x06CA6351, 0x14292967,
    0x27B70A85, 0x2E1B2138, 0x4D2C6DFC, 0x53380D13, 0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85,
    0xA2BFE8A1, 0xA81A664B, 0xC24B8B70, 0xC76C51A3, 0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070,
    0x19A4C116, 0x1E376C08, 0x2748774C, 0x34B0BCB5, 0x391C0CB3, 0x4ED8AA4A, 0x5B9CCA4F, 0x682E6FF3,
    0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208, 0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2,
]
PROTECTION_KEY_MAP = {
    "a": "accessMode",
    "b": "remoteProxyUnlocked",
    "c": "expiryEnabled",
    "d": "expiryTime",
    "e": "expiryRequiresAutomaticTime",
    "f": "hwidLockEnabled",
    "g": "hwids",
    "h": "loginHwidEnabled",
    "i": "loginHwidScheme",
    "j": "loginHwidAuthorizationRequired",
    "k": "legacyHwidEnabled",
    "l": "mobileDataOnly",
    "m": "blockRoot",
    "n": "legacyExtraProtectionEnabled",
    "o": "providerLockEnabled",
    "p": "providerCodes",
    "q": "providerMatchOperatorName",
    "r": "countryLockEnabled",
    "s": "countryCodes",
    "t": "blockApplicationsEnabled",
    "u": "blockedApplications",
    "v": "note",
    "w": "sshBannerAsNote",
    "x": "tunnelBanner",
}
# El banner ("x" -> "tunnelBanner") trae su propio JSON con letras.
# Se expande igual que el resto: v = version, s = style ("custom"),
# h = content (el texto del banner).
BANNER_KEY_MAP = {
    "v": "version",
    "s": "style",
    "h": "content",
}


class HC934Error(ValueError):
    pass


def _hkdf_sha256(ikm: bytes, salt: bytes, info: bytes, length: int = 32) -> bytes:
    if length < 0 or length > 255 * hashlib.sha256().digest_size:
        raise ValueError("invalid HKDF output length")
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    output = bytearray()
    previous = b""
    counter = 1
    while len(output) < length:
        previous = hmac.new(prk, previous + info + bytes([counter]), hashlib.sha256).digest()
        output.extend(previous)
        counter += 1
    return bytes(output[:length])


def _rol32(value: int, bits: int) -> int:
    return ((value << bits) & 0xFFFFFFFF) | (value >> (32 - bits))


def _ror32(x: int, n: int) -> int:
    return ((x >> n) | (x << (32 - n))) & 0xFFFFFFFF


def _quarter_round(state: List[int], a: int, b: int, c: int, d: int) -> None:
    state[a] = (state[a] + state[b]) & 0xFFFFFFFF
    state[d] = _rol32(state[d] ^ state[a], 16)
    state[c] = (state[c] + state[d]) & 0xFFFFFFFF
    state[b] = _rol32(state[b] ^ state[c], 12)
    state[a] = (state[a] + state[b]) & 0xFFFFFFFF
    state[d] = _rol32(state[d] ^ state[a], 8)
    state[c] = (state[c] + state[d]) & 0xFFFFFFFF
    state[b] = _rol32(state[b] ^ state[c], 7)


def _rounds(state: List[int]) -> None:
    for _ in range(10):
        _quarter_round(state, 0, 4, 8, 12)
        _quarter_round(state, 1, 5, 9, 13)
        _quarter_round(state, 2, 6, 10, 14)
        _quarter_round(state, 3, 7, 11, 15)
        _quarter_round(state, 0, 5, 10, 15)
        _quarter_round(state, 1, 6, 11, 12)
        _quarter_round(state, 2, 7, 8, 13)
        _quarter_round(state, 3, 4, 9, 14)


def _hchacha20(key: bytes, nonce16: bytes) -> bytes:
    if len(key) != 32 or len(nonce16) != 16:
        raise HC934Error("invalid HChaCha20 input length")
    state = list(
        struct.unpack("<4I", b"expand 32-byte k")
        + struct.unpack("<8I", key)
        + struct.unpack("<4I", nonce16)
    )
    _rounds(state)
    return struct.pack(
        "<8I",
        state[0], state[1], state[2], state[3],
        state[12], state[13], state[14], state[15],
    )


def _chacha20_block(key: bytes, nonce12: bytes, counter: int) -> bytes:
    if len(key) != 32 or len(nonce12) != 12:
        raise HC934Error("invalid ChaCha20 input length")
    initial = list(
        struct.unpack("<4I", b"expand 32-byte k")
        + struct.unpack("<8I", key)
        + (counter & 0xFFFFFFFF,)
        + struct.unpack("<3I", nonce12)
    )
    state = initial.copy()
    _rounds(state)
    return struct.pack(
        "<16I", *((state[i] + initial[i]) & 0xFFFFFFFF for i in range(16))
    )


def _stream_xor(data: bytes, key: bytes, nonce12: bytes, counter: int = 1) -> bytes:
    output = bytearray(len(data))
    for block_number, offset in enumerate(range(0, len(data), 64)):
        stream = _chacha20_block(key, nonce12, counter + block_number)
        chunk = data[offset:offset + 64]
        for i, value in enumerate(chunk):
            output[offset + i] = value ^ stream[i]
    return bytes(output)


def _poly1305(message: bytes, one_time_key: bytes) -> bytes:
    if len(one_time_key) != 32:
        raise HC934Error("invalid Poly1305 one-time key")
    r = int.from_bytes(one_time_key[:16], "little") & 0x0FFFFFFC0FFFFFFC0FFFFFFC0FFFFFFF
    pad = int.from_bytes(one_time_key[16:], "little")
    accumulator = 0
    modulus = (1 << 130) - 5
    for offset in range(0, len(message), 16):
        block = message[offset:offset + 16]
        accumulator = ((accumulator + int.from_bytes(block + b"\x01", "little")) * r) % modulus
    return ((accumulator + pad) & ((1 << 128) - 1)).to_bytes(16, "little")


def _pad16(data: bytes) -> bytes:
    return b"" if len(data) % 16 == 0 else b"\x00" * (16 - len(data) % 16)


def _xchacha20poly1305_decrypt_pure(
    key: bytes, nonce: bytes, aad: bytes, ciphertext_and_tag: bytes
) -> bytes:
    subkey = _hchacha20(key, nonce[:16])
    nonce12 = b"\x00\x00\x00\x00" + nonce[16:]
    ciphertext = ciphertext_and_tag[:-16]
    supplied_tag = ciphertext_and_tag[-16:]
    one_time_key = _chacha20_block(subkey, nonce12, 0)[:32]
    mac_input = (
        aad + _pad16(aad)
        + ciphertext + _pad16(ciphertext)
        + struct.pack("<Q", len(aad))
        + struct.pack("<Q", len(ciphertext))
    )
    expected_tag = _poly1305(mac_input, one_time_key)
    if not hmac.compare_digest(expected_tag, supplied_tag):
        raise HC934Error("XChaCha20-Poly1305 authentication failed")
    return _stream_xor(ciphertext, subkey, nonce12, 1)


def _xchacha20poly1305_decrypt(
    key: bytes, nonce: bytes, aad: bytes, ciphertext_and_tag: bytes
) -> bytes:
    if len(key) != 32:
        raise HC934Error(f"invalid XChaCha20 key length: {len(key)}")
    if len(nonce) != 24:
        raise HC934Error(f"invalid XChaCha20 nonce length: {len(nonce)}")
    if len(ciphertext_and_tag) < 16:
        raise HC934Error("ciphertext is shorter than its Poly1305 tag")
    try:
        cipher = ChaCha20_Poly1305.new(key=key, nonce=nonce)
        cipher.update(aad)
        return cipher.decrypt_and_verify(ciphertext_and_tag[:-16], ciphertext_and_tag[-16:])
    except ImportError:
        pass
    except ValueError as exc:
        raise HC934Error("XChaCha20-Poly1305 authentication failed") from exc
    try:
        from nacl.bindings import crypto_aead_xchacha20poly1305_ietf_decrypt
        from nacl.exceptions import CryptoError
        return crypto_aead_xchacha20poly1305_ietf_decrypt(ciphertext_and_tag, aad, nonce, key)
    except ImportError:
        return _xchacha20poly1305_decrypt_pure(key, nonce, aad, ciphertext_and_tag)
    except CryptoError as exc:
        raise HC934Error("XChaCha20-Poly1305 authentication failed") from exc


def _argon2id13(
    password: bytes, salt: bytes, opslimit: int, memlimit: int, length: int = 32
) -> bytes:
    if len(salt) != 16:
        raise HC934Error(f"ARGON2ID13 salt must be 16 bytes, got {len(salt)}")
    if opslimit <= 0 or memlimit <= 0 or memlimit % 1024:
        raise HC934Error("invalid ARGON2ID13 limits in envelope")
    try:
        from nacl.pwhash import argon2id
        return argon2id.kdf(length, password, salt, opslimit=opslimit, memlimit=memlimit)
    except ImportError:
        pass
    try:
        from argon2.low_level import Type, hash_secret_raw
        return hash_secret_raw(
            password, salt, time_cost=opslimit, memory_cost=memlimit // 1024,
            parallelism=1, hash_len=length, type=Type.ID, version=19,
        )
    except ImportError:
        pass
    try:
        from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
        return Argon2id(
            salt=salt, length=length, iterations=opslimit,
            lanes=1, memory_cost=memlimit // 1024,
        ).derive(password)
    except (ImportError, AttributeError):
        pass
    try:
        import ctypes
        import ctypes.util
        candidates = [
            "libsodium.so.23", "libsodium.so", "libargon2.so.1", "libargon2.so",
            "/data/data/com.termux/files/usr/lib/libsodium.so",
            "/data/data/com.termux/files/usr/lib/libargon2.so",
        ]
        s_found = ctypes.util.find_library("sodium")
        if s_found and s_found not in candidates:
            candidates.insert(0, s_found)
        a_found = ctypes.util.find_library("argon2")
        if a_found and a_found not in candidates:
            candidates.insert(0, a_found)
        for soname in candidates:
            try:
                lib = ctypes.CDLL(soname)
                if hasattr(lib, "crypto_pwhash"):
                    out = (ctypes.c_ubyte * length)()
                    ret = lib.crypto_pwhash(
                        out, ctypes.c_ulonglong(length), password,
                        ctypes.c_ulonglong(len(password)), salt,
                        ctypes.c_ulonglong(opslimit), ctypes.c_size_t(memlimit),
                        ctypes.c_int(2),
                    )
                    if ret == 0:
                        return bytes(out)
                elif hasattr(lib, "argon2id_hash_raw"):
                    out = (ctypes.c_ubyte * length)()
                    ret = lib.argon2id_hash_raw(
                        ctypes.c_uint32(opslimit), ctypes.c_uint32(memlimit // 1024),
                        ctypes.c_uint32(1), password, len(password),
                        salt, len(salt), out, length,
                    )
                    if ret == 0:
                        return bytes(out)
            except (OSError, AttributeError):
                continue
    except Exception:
        pass
    raise RuntimeError(
        "password-protected .hc support requires pynacl, argon2-cffi, cryptography, or libsodium"
    )


def _sha256_compress_v4(state: List[int], block: bytes) -> List[int]:
    if len(block) != 64:
        raise HC934Error("internal V4 SHA-256 block must be 64 bytes")
    w = list(struct.unpack(">16I", block)) + [0] * 48
    for i in range(16, 64):
        x, y = w[i - 15], w[i - 2]
        s0 = _ror32(x, 7) ^ _ror32(x, 18) ^ (x >> 3)
        s1 = _ror32(y, 17) ^ _ror32(y, 19) ^ (y >> 10)
        w[i] = (w[i - 16] + s0 + w[i - 7] + s1) & 0xFFFFFFFF
    a, b, c, d, e, f, g, h = state
    for i in range(64):
        s1 = _ror32(e, 6) ^ _ror32(e, 11) ^ _ror32(e, 25)
        ch = (e & f) ^ ((~e) & g)
        t1 = (h + s1 + ch + V4_SHA256_K[i] + w[i]) & 0xFFFFFFFF
        s0 = _ror32(a, 2) ^ _ror32(a, 13) ^ _ror32(a, 22)
        maj = (a & b) ^ (a & c) ^ (b & c)
        t2 = (s0 + maj) & 0xFFFFFFFF
        h, g, f, e, d, c, b, a = g, f, e, (d + t1) & 0xFFFFFFFF, c, b, a, (t1 + t2) & 0xFFFFFFFF
    return [(x + y) & 0xFFFFFFFF for x, y in zip(state, [a, b, c, d, e, f, g, h])]


def _finish_hmac_state_v4(state: List[int], data: bytes) -> bytes:
    data = bytes(data)
    padded = bytearray(data)
    padded.append(0x80)
    while len(padded) % 64 != 56:
        padded.append(0)
    padded.extend(((64 + len(data)) * 8).to_bytes(8, "big"))
    st = list(state)
    for off in range(0, len(padded), 64):
        st = _sha256_compress_v4(st, padded[off:off + 64])
    return b"".join(x.to_bytes(4, "big") for x in st)


def _c0_v4(prefix: bytes) -> bytes:
    material = b"\xe9" + V4_CERT_DIGEST + prefix
    inner = _finish_hmac_state_v4(V4_IPAD_STATE, material)
    return _finish_hmac_state_v4(V4_OPAD_STATE, inner)


def _derive_n15(salt: bytes, aad: bytes) -> bytes:
    inner = _finish_hmac_state_v4(N15_IPAD_STATE, b"\xf1" + V4_CERT_DIGEST + aad)
    outer = _finish_hmac_state_v4(N15_OPAD_STATE, inner)
    return _hkdf_sha256(outer, salt, b"hc-config-content-v12")



def _derive_n19(salt: bytes, aad: bytes) -> bytes:
    inner = _finish_hmac_state_v4(N19_IPAD_STATE, b"\xf1" + V4_CERT_DIGEST + aad)
    outer = _finish_hmac_state_v4(N19_OPAD_STATE, inner)
    return _hkdf_sha256(outer, salt, b"hc-config-content-v14")

def _hkdf_layer(key: bytes, info_label: bytes, section_aad: bytes) -> bytes:
    return _hkdf_sha256(key, info_label, section_aad)


def _v4_outer_key() -> bytes:
    return _hkdf_sha256(_c0_v4(V4_OUTER_SEED), V4_OUTER_SALT, V4_OUTER_INFO)


def _v4_logical_bytes(raw: bytes) -> bytes:
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise HC934Error("file is not in UTF-8 byte-carrier format") from exc
    if any(ord(ch) > 255 for ch in text):
        raise HC934Error("file contains non-byte Unicode characters")
    return bytes(ord(ch) for ch in text)


def _open_outer_934(file_bytes: bytes) -> Dict[str, Any]:
    key = _v4_outer_key()
    last_error: Optional[Exception] = None
    seen = set()
    current = file_bytes
    for _ in range(6):
        if current in seen:
            break
        seen.add(current)
        if len(current) >= 40:
            try:
                logical = _v4_logical_bytes(current)
                plaintext = _xchacha20poly1305_decrypt(
                    key, logical[:24], V4_OUTER_AAD, logical[24:]
                )
                env = json.loads(plaintext.decode("utf-8"))
                if isinstance(env, dict) and env.get("a") == "HCCFG":
                    b = int(env.get("b", 0))
                    if (
                        (b == 10 and str(env.get("e")) in ("n11", "n12"))
                        or (b == 12 and str(env.get("e")) == "n15")
                        or (b == 14 and str(env.get("e")) == "n19")
                    ):
                        return env
                    if b in (11, 13) or str(env.get("e")) == "n13" or "p" in env:
                        raise HC934Error(
                            "Extra Protection (schema n13) requires online activation + device-security check"
                        )
                    raise HC934Error(
                        f"unsupported schema/schedule: schema={env.get('b')!r}, schedule={env.get('e')!r}"
                    )
                raise HC934Error("unexpected outer envelope magic")
            except HC934Error as exc:
                if "Extra Protection" in str(exc) or "unsupported schema" in str(exc):
                    raise
                last_error = exc
            except Exception as exc:
                last_error = exc
        try:
            text = current.decode("utf-8")
        except UnicodeDecodeError:
            break
        if not all(ord(ch) <= 0xFF for ch in text):
            break
        logical = bytes(ord(ch) for ch in text)
        if logical == current:
            break
        current = logical
    raise HC934Error(f"not a supported 934 .hc outer envelope ({last_error})")


def _norm_hwid(hwid: str) -> bytes:
    cleaned = re.sub(r"[^0-9A-Za-z]", "", str(hwid))
    if len(cleaned) != 32 or any(c not in "0123456789abcdefABCDEFhH" for c in cleaned):
        raise HC934Error("HWID must normalize to 32 hexadecimal characters")
    return cleaned.upper().encode()


def _validate_envelope_934(env: Dict[str, Any]) -> Tuple[int, str, bytes]:
    schema = int(env.get("b", 0))
    sched = env.get("e")
    if schema in (11, 13) or sched == "n13" or "p" in env:
        raise HC934Error(
            "Extra Protection (schema n13) requires online activation + device-security check"
        )
    if not ((schema == 10 and sched in ("n11", "n12")) or ((schema in (12, 14)) and sched == "n15") or (schema == 14 and sched == "n19") or (schema == 14 and sched == "n19")):
        raise HC934Error(f"unsupported schema/schedule: schema={schema}, schedule={sched!r}")
    hflag = env.get("h", 0)
    if hflag not in (0, 1, False, True):
        raise HC934Error(f"unsupported password flag: {hflag!r}")
    try:
        ekey = bytes.fromhex(env["g"])
    except (KeyError, TypeError, ValueError) as exc:
        raise HC934Error("invalid envelope key/salt") from exc
    if len(ekey) != 32:
        raise HC934Error("invalid envelope key/salt length")
    return schema, sched, ekey


def _transcript_934(env: Dict[str, Any], ekey: bytes, hwid: Optional[str] = None) -> bytes:
    features = ",".join(env.get("f", [])).encode()
    transcript = b"HCCFG\x00" + V4_PACKAGE + b"\x00" + b"1\x00" + features + b"\x00"
    if env.get("n") is not None:
        n = int(env["n"])
        if n < 0:
            raise HC934Error("invalid reader version")
        transcript += str(n).encode() + b"\x00"
    if hwid is not None:
        transcript += b"hwid\x00" + _norm_hwid(hwid) + b"\x00"
    transcript += ekey
    return transcript


def _info_934(env: Dict[str, Any], hwid: Optional[str] = None) -> bytes:
    features = ",".join(env.get("f", [])).encode()
    info = b"app-config|" + str(env["e"]).encode() + b"|" + V4_PACKAGE + b"|1|" + features
    if env.get("n") is not None:
        info += b"|" + str(int(env["n"])).encode()
    if hwid is not None:
        info += b"|hwid|" + _norm_hwid(hwid)
    return info


def _aad_base_934(env: Dict[str, Any], password_protected: bool = False) -> bytes:
    features = ",".join(env.get("f", [])).encode()
    aad = (
        b"HCCFG|" + str(int(env["b"])).encode()
        + b"|XCHACHA20P1305|NATIVE-HKDF-SHA256|"
        + str(env["e"]).encode() + b"|" + V4_PACKAGE + b"|1|" + features
    )
    if password_protected:
        try:
            ops, mem = int(env["l"]), int(env["m"])
        except (KeyError, TypeError, ValueError) as exc:
            raise HC934Error("password KDF parameters are missing") from exc
        kdf_name = b"ARGON2ID13" if env.get("k") == "a1" else str(env.get("k")).encode()
        aad += b"|1|" + kdf_name + b"|" + str(ops).encode() + b"|" + str(mem).encode()
    else:
        aad += b"|0"
    if env.get("n") is not None:
        aad += b"|" + str(int(env["n"])).encode()
    return aad


def _section_material_934(
    env: Dict[str, Any], password: Optional[str] = None, hwid: Optional[str] = None
) -> Tuple[bytes, bytes, int]:
    schema, sched, ekey = _validate_envelope_934(env)
    protected = bool(env.get("h", 0))
    is_hwid = sched == "n12"
    if is_hwid and hwid is None and protected:
        raise HC934Error("HWID + password protected .hc file; provide both HWID and password")
    if protected and password is None:
        raise HC934Error("password-protected .hc file; provide password")
    if is_hwid and hwid is None:
        raise HC934Error("HWID-protected .hc file; provide HWID")
    transcript = _transcript_934(env, ekey, hwid if is_hwid else None)
    info = _info_934(env, hwid if is_hwid else None)
    aad_base = _aad_base_934(env, password_protected=protected)
    if schema in (12, 14):
        contact_key = _derive_n19(ekey, aad_base) if schema == 14 else _derive_n15(ekey, aad_base)
        if protected:
            try:
                ops, mem = int(env["l"]), int(env["m"])
            except (KeyError, TypeError, ValueError) as exc:
                raise HC934Error("password KDF parameters are invalid") from exc
            contact_key = _hkdf_sha256(
                contact_key + _argon2id13(password.encode("utf-8"), ekey[:16], ops, mem),
                ekey,
                info,
            )
        return contact_key, aad_base, schema

    ikm = _c0_v4(transcript)
    if protected:
        try:
            ops, mem = int(env["l"]), int(env["m"])
        except (KeyError, TypeError, ValueError) as exc:
            raise HC934Error("password KDF parameters are invalid") from exc
        ikm += _argon2id13(password.encode("utf-8"), ekey[:16], ops, mem)
    base_key = _hkdf_sha256(ikm, ekey, info)
    section_key = base_key
    if is_hwid:
        slots = env.get("o")
        if not isinstance(slots, list) or not slots:
            raise HC934Error("HWID schedule has no key slots")
        for slot in slots:
            try:
                candidate = _xchacha20poly1305_decrypt(
                    base_key,
                    bytes.fromhex(slot["a"]),
                    aad_base + b"\x00w",
                    bytes.fromhex(slot["b"]),
                )
                if len(candidate) == 32:
                    return candidate, aad_base, schema
            except (KeyError, TypeError, ValueError, HC934Error):
                continue
        raise HC934Error("HWID does not match any authenticated key slot")
    return section_key, aad_base, schema


class _HPC1Reader:
    def __init__(self, data: bytes):
        self.data = data
        self.offset = 0

    def take(self, size: int) -> bytes:
        if size < 0 or self.offset + size > len(self.data):
            raise HC934Error("truncated HPC1 record")
        value = self.data[self.offset : self.offset + size]
        self.offset += size
        return value

    def u32(self) -> int:
        return struct.unpack(">I", self.take(4))[0]

    def u64(self) -> int:
        return struct.unpack(">Q", self.take(8))[0]

    def text(self) -> str:
        size = self.u32()
        if size > 16 * 1024 * 1024:
            raise HC934Error("implausible HPC1 string length")
        return self.take(size).decode("utf-8")


def parse_hpc1_934(data: bytes, label: Optional[str] = None) -> Dict[str, Any]:
    reader = _HPC1Reader(data)
    if reader.take(4) != b"HPC1":
        raise HC934Error("section is not an HPC1 record")
    field_count = reader.u32()
    if field_count != 11:
        raise HC934Error(f"unsupported HPC1 field count: {field_count}")
    name = reader.text()
    protocol = reader.text()
    host = reader.text()
    port = reader.u32()
    username = reader.text()
    password = reader.text()
    payload = reader.text()
    options_text = reader.text()
    flags = reader.u32()
    updated_at_ms = reader.u64()
    mode = reader.text()
    if reader.offset != len(data):
        raise HC934Error("trailing bytes after HPC1 record")
    try:
        options_obj: Any = json.loads(options_text) if options_text else {}
    except json.JSONDecodeError:
        options_obj = options_text
    item: Dict[str, Any] = {
        "label": label or "",
        "name": name,
        "protocol": protocol,
        "host": host,
        "port": port,
        "username": username,
        "password": password,
        "payload": payload,
        "options": options_obj,
        "flags": flags,
        "updated_at_ms": updated_at_ms,
        "mode": mode,
    }
    if not isinstance(options_obj, dict) and options_text:
        item["options_text"] = options_text
    return item


def _decrypt_parts_934(
    file_bytes: bytes, password: Optional[str] = None, hwid: Optional[str] = None
) -> Tuple[Dict[str, Any], bytes, List[Tuple[str, bytes, Optional[bytes]]]]:
    env = _open_outer_934(file_bytes)
    contact_key, aad_base, schema = _section_material_934(env, password=password, hwid=hwid)

    def open_section(key: bytes, label: str, nonce_hex: str, ct_hex: str) -> bytes:
        section_aad = aad_base + b"\x00" + label.encode("utf-8")
        if schema in (12, 14):
            key = _hkdf_layer(key, b"hc-config-part-v12", section_aad)
        return _xchacha20poly1305_decrypt(
            key, bytes.fromhex(nonce_hex), section_aad, bytes.fromhex(ct_hex)
        )

    main_section = env.get("i")
    if not isinstance(main_section, dict):
        raise HC934Error("main section is missing")
    try:
        main_plaintext = open_section(contact_key, "m", main_section["b"], main_section["c"])
    except HC934Error as exc:
        if "authentication failed" in str(exc).lower():
            raise HC934Error("authentication failed: wrong password/HWID for this .hc file") from exc
        raise

    raw_sections = env.get("j", [])
    if isinstance(raw_sections, dict):
        raw_sections = list(raw_sections.values())
    if not isinstance(raw_sections, list):
        raise HC934Error("profile-section collection is invalid")

    sections: List[Tuple[str, bytes, Optional[bytes]]] = []
    for section in raw_sections:
        if not isinstance(section, dict):
            raise HC934Error("profile-section collection is invalid")
        label = section.get("a")
        if not isinstance(label, str) or not label:
            raise HC934Error("section label is invalid")
        try:
            plaintext = open_section(contact_key, label, section["b"], section["c"])
        except HC934Error as exc:
            if "authentication failed" in str(exc).lower():
                raise HC934Error("authentication failed: wrong password/HWID for this .hc file") from exc
            raise

        sidecar = None
        nested = section.get("d")
        if nested is not None:
            if not isinstance(nested, dict):
                raise HC934Error("invalid profile payload sidecar")
            sidecar_aad = aad_base + b"\x00" + label.encode("utf-8") + b":x"
            sidecar_key = (
                _hkdf_layer(contact_key, b"hc-config-part-v12", sidecar_aad)
                if (schema in (12, 14)) else contact_key
            )
            sidecar = _xchacha20poly1305_decrypt(
                sidecar_key, bytes.fromhex(nested["a"]), sidecar_aad, bytes.fromhex(nested["b"])
            )

        if plaintext.startswith(b"HPR1") and len(plaintext) >= 44:
            reg_aad = aad_base + b"\x00" + label.encode("utf-8") + b":r"
            reg_key = (
                _hkdf_layer(contact_key, b"hc-config-part-v12", reg_aad)
                if (schema in (12, 14)) else contact_key
            )
            plaintext = _xchacha20poly1305_decrypt(
                reg_key, plaintext[4:28], reg_aad, plaintext[28:]
            )

        sections.append((label, plaintext, sidecar))

    return env, main_plaintext, sections


_BUILD_NAMES = {934: "8.0.22 Patch 2", 942: "8.1.5"}

def _format_app_version(env: Dict[str, Any]) -> str:
    n = env.get("n")
    try:
        code = int(n)
        name = _BUILD_NAMES.get(code, "build")
        return f"{name} ({code})"
    except (TypeError, ValueError):
        return V4_VERSION_LABEL_934


def decrypt_hc_934(
    file_bytes: bytes, password: Optional[str] = None, hwid: Optional[str] = None
) -> Dict[str, Any]:
    env, main_plaintext, sections = _decrypt_parts_934(file_bytes, password=password, hwid=hwid)
    try:
        main_config = json.loads(main_plaintext.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise HC934Error("main section is not valid UTF-8 JSON") from exc

    configs: List[Dict[str, Any]] = []
    other_sections: List[Dict[str, Any]] = []
    for label, plaintext, sidecar in sections:
        if plaintext.startswith(b"HPC1"):
            parsed = parse_hpc1_934(plaintext, label=label)
            if sidecar is not None:
                try:
                    parsed["custom_payload_sidecar"] = sidecar.decode("utf-8")
                except UnicodeDecodeError:
                    parsed["custom_payload_sidecar_hex"] = sidecar.hex()
            configs.append(parsed)
            continue

        try:
            decoded: Any = plaintext.decode("utf-8")
            if decoded.startswith(("{", "[")):
                decoded = json.loads(decoded)
        except (UnicodeDecodeError, json.JSONDecodeError):
            decoded = {"hex": plaintext.hex()}
        other_sections.append({"label": label, "content": decoded})

    raw_prot = main_config.get("g", {}) if isinstance(main_config, dict) else {}
    protections = (
        {PROTECTION_KEY_MAP.get(k, k): v for k, v in raw_prot.items()}
        if isinstance(raw_prot, dict) else raw_prot
    )
    # El banner trae su propio JSON anidado con letras (v/s/h);
    # se parsea igual que el resto en vez de dejarlo tal cual.
    if isinstance(protections, dict):
        banner = protections.get("tunnelBanner")
        if isinstance(banner, dict):
            protections["tunnelBanner"] = {
                BANNER_KEY_MAP.get(k, k): v for k, v in banner.items()
            }

    result: Dict[str, Any] = {
        "app_version": _format_app_version(env),
        "config": configs,
        "protections": protections,
    }
    if other_sections:
        result["other_sections"] = other_sections
    return result


def _extract_hwid_value(raw: Optional[str]) -> Optional[str]:
    if not isinstance(raw, str):
        return None
    cleaned = re.sub(r"[^0-9A-Za-z]", "", raw)
    if not cleaned:
        return None
    if re.fullmatch(r"[0-9a-fAhH]{32}", cleaned):
        return cleaned
    match = re.search(r"[0-9a-fAhH]{32}", cleaned)
    return match.group(0) if match else None


def _parse_auth_inputs(
    password: Optional[str] = None, hwid: Optional[str] = None
) -> Tuple[Optional[str], Optional[str]]:
    parsed_password = password if isinstance(password, str) and password.strip() else None
    parsed_hwid = hwid
    if isinstance(password, str):
        text = password.strip()
        if text:
            pass_match = re.search(
                r"(?im)^\s*(?:only\s+)?pass(?:word)?\s*(?:[:\-–—=]\s*|\s+)(.+?)\s*$", text
            )
            hwid_match = re.search(
                r"(?im)^\s*hwid\s*(?:[:\-–—=]\s*|\s+)(.+?)\s*$", text
            )
            if pass_match:
                parsed_password = pass_match.group(1).strip()
            if hwid_match:
                parsed_hwid = _extract_hwid_value(hwid_match.group(1))
                if not pass_match:
                    parsed_password = None
            if parsed_hwid is None and not pass_match:
                bare = _extract_hwid_value(text)
                if bare and re.fullmatch(r"[0-9a-fAhH]{32}", re.sub(r"[^0-9A-Za-z]", "", text)):
                    parsed_hwid = bare
                    parsed_password = None
    return parsed_password, parsed_hwid


def run(file_bytes, password: Optional[str] = None, hwid: Optional[str] = None) -> str:
    password, hwid = _parse_auth_inputs(password, hwid)
    data = file_bytes
    if isinstance(data, str):
        try:
            data = data.encode("latin-1")
        except UnicodeEncodeError:
            data = data.encode("utf-8")
    if not isinstance(data, bytes) or not data:
        return "⚠️ **DECRYPTION FAILED:**\nInvalid or empty input data."

    try:
        unpacked = decrypt_hc_934(data, password=password, hwid=hwid)
        return json.dumps(unpacked, indent=2, ensure_ascii=False)
    except HC934Error as exc:
        msg = str(exc)
        lower = msg.lower()
        if "both hwid and password" in lower:
            return "⚠️ **HWID + PASSWORD REQUIRED**\n\n"
        if "provide hwid" in lower or "hwid-protected" in lower:
            return "⚠️ **HWID REQUIRED**\n\n"
        if "provide password" in lower or "password-protected" in lower:
            return "⚠️ **PASSWORD REQUIRED**\n\n"
        if "authentication failed" in lower or "does not match any authenticated" in lower:
            return "⚠️ **WRONG PASSWORD / HWID**\n\n"
        return f"⚠️ **DECRYPTION FAILED:**\n{msg}"
    except Exception as exc:
        return f"⚠️ **DECRYPTION FAILED:**\n{exc}"

if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Usage: python hc934_only.py <file.hc> [password] [hwid]")
        sys.exit(1)

    hc_path = sys.argv[1]
    pw_arg = sys.argv[2] if len(sys.argv) > 2 else None
    hwid_arg = sys.argv[3] if len(sys.argv) > 3 else None

    with open(hc_path, "rb") as f:
        raw_bytes = f.read()

    print(run(raw_bytes, password=pw_arg, hwid=hwid_arg))

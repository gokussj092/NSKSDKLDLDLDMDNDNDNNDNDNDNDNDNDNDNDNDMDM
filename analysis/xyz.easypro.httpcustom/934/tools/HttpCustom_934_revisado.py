import hashlib
import hmac
import json
import struct
import os
import base64
import binascii
import re
import math
from typing import Any, Dict, Iterable, List, Optional, Tuple
try:
    from Crypto.Cipher import ChaCha20, AES
    from Crypto.Util.Padding import unpad
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False
PACKAGE = b"xyz.easypro.httpcustom"
OUTER_AAD = b"HCX1|xyz.easypro.httpcustom|1"
OUTER_SEED = b"hc-envelope-seal-v1 xyz.easypro.httpcustom"
OUTER_HKDF_SALT = b"hc-envelope-seal-salt-v1"
OUTER_HKDF_INFO = b"hc-envelope-seal-info-v1"
OUTER_KEY_V3 = bytes.fromhex(
    "88702df6ae8c089c9478b8cd2bd3f30961b3574a58063d024bdc50f6b779e26f"
)
N7_HMAC_KEY = bytes.fromhex(
    "9ba7ff3baf33db7aad807a86574b7ca55bef2f048ead51f3a1fe0cff389db3b3"
)
C0_SHA256_PREFIX = bytes.fromhex(
    "95dd433d7e4a0be02d55cc62553edcfc8f077fe780be5a7da7f861c2558dc181"
    "38cabb40b2f81a5a30b11a97cbcf0fed755aa8c2b5495e9bc0c1902077a4cd92"
)
class HCDecryptError(ValueError):
    pass
def _c0_digest(data: bytes) -> bytes:
    return hashlib.sha256(C0_SHA256_PREFIX + data).digest()
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
        raise HCDecryptError("invalid HChaCha20 input length")
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
        raise HCDecryptError("invalid ChaCha20 input length")
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
        raise HCDecryptError("invalid Poly1305 one-time key")
    r = int.from_bytes(one_time_key[:16], "little")
    r &= 0x0FFFFFFC0FFFFFFC0FFFFFFC0FFFFFFF
    pad = int.from_bytes(one_time_key[16:], "little")
    accumulator = 0
    modulus = (1 << 130) - 5
    for offset in range(0, len(message), 16):
        block = message[offset:offset + 16]
        accumulator = (
            (accumulator + int.from_bytes(block + b"\x01", "little")) * r
        ) % modulus
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
        raise HCDecryptError("XChaCha20-Poly1305 authentication failed")
    return _stream_xor(ciphertext, subkey, nonce12, 1)
def _xchacha20poly1305_encrypt_pure(
    key: bytes, nonce: bytes, aad: bytes, plaintext: bytes
) -> bytes:
    subkey = _hchacha20(key, nonce[:16])
    nonce12 = b"\x00\x00\x00\x00" + nonce[16:]
    ciphertext = _stream_xor(plaintext, subkey, nonce12, 1)
    one_time_key = _chacha20_block(subkey, nonce12, 0)[:32]
    mac_input = (
        aad + _pad16(aad)
        + ciphertext + _pad16(ciphertext)
        + struct.pack("<Q", len(aad))
        + struct.pack("<Q", len(ciphertext))
    )
    return ciphertext + _poly1305(mac_input, one_time_key)
def _argon2id13(
    password: bytes, salt: bytes, opslimit: int, memlimit: int, length: int = 32
) -> bytes:
    if len(salt) != 16:
        raise HCDecryptError(f"ARGON2ID13 salt must be 16 bytes, got {len(salt)}")
    if opslimit <= 0 or memlimit <= 0 or memlimit % 1024:
        raise HCDecryptError("invalid ARGON2ID13 limits in envelope")
    try:
        from nacl.pwhash import argon2id  # type: ignore
        return argon2id.kdf(
            length,
            password,
            salt,
            opslimit=opslimit,
            memlimit=memlimit,
        )
    except ImportError:
        pass
    try:
        from argon2.low_level import Type, hash_secret_raw  # type: ignore
        return hash_secret_raw(
            password,
            salt,
            time_cost=opslimit,
            memory_cost=memlimit // 1024,
            parallelism=1,
            hash_len=length,
            type=Type.ID,
            version=19,
        )
    except ImportError:
        pass
    try:
        from cryptography.hazmat.primitives.kdf.argon2 import Argon2id  # type: ignore
        return Argon2id(
            salt=salt,
            length=length,
            iterations=opslimit,
            lanes=1,
            memory_cost=memlimit // 1024,
        ).derive(password)
    except (ImportError, AttributeError):
        pass
    try:
        import ctypes
        import ctypes.util
        candidates = [
            "libsodium.so.23",
            "libsodium.so",
            "libargon2.so.1",
            "libargon2.so",
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
                        out,
                        ctypes.c_ulonglong(length),
                        password,
                        ctypes.c_ulonglong(len(password)),
                        salt,
                        ctypes.c_ulonglong(opslimit),
                        ctypes.c_size_t(memlimit),
                        ctypes.c_int(2),
                    )
                    if ret == 0:
                        return bytes(out)
                elif hasattr(lib, "argon2id_hash_raw"):
                    out = (ctypes.c_ubyte * length)()
                    ret = lib.argon2id_hash_raw(
                        ctypes.c_uint32(opslimit),
                        ctypes.c_uint32(memlimit // 1024),
                        ctypes.c_uint32(1),
                        password,
                        len(password),
                        salt,
                        len(salt),
                        out,
                        length,
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
def _xchacha20poly1305_decrypt(
    key: bytes, nonce: bytes, aad: bytes, ciphertext_and_tag: bytes
) -> bytes:
    if len(key) != 32:
        raise HCDecryptError(f"invalid XChaCha20 key length: {len(key)}")
    if len(nonce) != 24:
        raise HCDecryptError(f"invalid XChaCha20 nonce length: {len(nonce)}")
    if len(ciphertext_and_tag) < 16:
        raise HCDecryptError("ciphertext is shorter than its Poly1305 tag")
    try:
        from Crypto.Cipher import ChaCha20_Poly1305  # type: ignore
        cipher = ChaCha20_Poly1305.new(key=key, nonce=nonce)
        cipher.update(aad)
        return cipher.decrypt_and_verify(ciphertext_and_tag[:-16], ciphertext_and_tag[-16:])
    except ImportError:
        pass
    except ValueError as exc:
        raise HCDecryptError("XChaCha20-Poly1305 authentication failed") from exc
    try:
        from nacl.bindings import crypto_aead_xchacha20poly1305_ietf_decrypt  # type: ignore
        from nacl.exceptions import CryptoError  # type: ignore
    except ImportError:
        return _xchacha20poly1305_decrypt_pure(key, nonce, aad, ciphertext_and_tag)
    try:
        return crypto_aead_xchacha20poly1305_ietf_decrypt(
            ciphertext_and_tag, aad, nonce, key
        )
    except CryptoError as exc:
        raise HCDecryptError("XChaCha20-Poly1305 authentication failed") from exc
def _xchacha20poly1305_encrypt(
    key: bytes, nonce: bytes, aad: bytes, plaintext: bytes
) -> bytes:
    if len(key) != 32:
        raise HCDecryptError(f"invalid XChaCha20 key length: {len(key)}")
    if len(nonce) != 24:
        raise HCDecryptError(f"invalid XChaCha20 nonce length: {len(nonce)}")
    try:
        from Crypto.Cipher import ChaCha20_Poly1305  # type: ignore
        cipher = ChaCha20_Poly1305.new(key=key, nonce=nonce)
        cipher.update(aad)
        ciphertext, tag = cipher.encrypt_and_digest(plaintext)
        return ciphertext + tag
    except ImportError:
        pass
    try:
        from nacl.bindings import crypto_aead_xchacha20poly1305_ietf_encrypt  # type: ignore
    except ImportError:
        return _xchacha20poly1305_encrypt_pure(key, nonce, aad, plaintext)
    return crypto_aead_xchacha20poly1305_ietf_encrypt(
        plaintext, aad, nonce, key
    )
def _outer_key() -> bytes:
    ikm = _c0_digest(OUTER_SEED)
    return _hkdf_sha256(ikm, OUTER_HKDF_SALT, OUTER_HKDF_INFO)
def _carrier_candidates(file_bytes: bytes) -> Iterable[bytes]:
    seen = set()
    current = file_bytes
    for _ in range(6):
        if current in seen:
            break
        seen.add(current)
        if len(current) >= 24 + 16:
            yield current
        try:
            text = current.decode("utf-8")
        except UnicodeDecodeError:
            break
        if not all(ord(char) <= 0xFF for char in text):
            break
        logical = bytes(ord(char) for char in text)
        if logical == current:
            break
        current = logical
def _open_outer_envelope(file_bytes: bytes) -> Dict[str, Any]:
    key = _outer_key()
    last_error: Optional[Exception] = None
    for logical in _carrier_candidates(file_bytes):
        if len(logical) < 24 + 16:
            continue
        try:
            plaintext = _xchacha20poly1305_decrypt(
                key, logical[:24], OUTER_AAD, logical[24:]
            )
            value = json.loads(plaintext.decode("utf-8"))
            if not isinstance(value, dict):
                raise HCDecryptError("outer plaintext is not a JSON object")
            return value
        except (HCDecryptError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            last_error = exc
        try:
            nonce = logical[:24]
            ciphertext = logical[24:-16]
            subkey = _hchacha20(OUTER_KEY_V3, nonce[:16])
            nonce12 = b"\x00\x00\x00\x00" + nonce[16:]
            plaintext = _stream_xor(ciphertext, subkey, nonce12, 1)
            value = json.loads(plaintext.decode("utf-8"))
            if isinstance(value, dict) and value.get("a") == "HCCFG":
                return value
        except (HCDecryptError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            last_error = exc
    raise HCDecryptError(
        "not an authentic supported HTTP Custom configuration envelope"
    ) from last_error
def _validate_envelope(envelope: Dict[str, Any]) -> int:
    if envelope.get("a") != "HCCFG":
        raise HCDecryptError(f"unsupported envelope magic {envelope.get('a')!r}")
    try:
        schema = int(envelope.get("b"))
    except (TypeError, ValueError) as exc:
        raise HCDecryptError("invalid envelope schema") from exc
    if schema == 1:
        expected_cipher = "XCHACHA20P1305"
        expected_kdf = "NATIVE-HKDF-SHA256"
    elif schema in (2, 5, 7):
        expected_cipher = "s1"
        expected_kdf = "h1"
    else:
        raise HCDecryptError(f"unsupported envelope schema b={schema!r}")
    checks = {
        "c": expected_cipher,
        "d": expected_kdf,
    }
    for field, wanted in checks.items():
        actual = envelope.get(field)
        if actual != wanted:
            raise HCDecryptError(
                f"unsupported envelope field {field!r}: {actual!r}; expected {wanted!r}"
            )
    schedule = envelope.get("e")
    if schedule not in ("n1", "n2", "n7", "n8"):
        raise HCDecryptError(
            f"unsupported envelope field 'e': {schedule!r}; expected 'n1', 'n2', 'n7', or 'n8'"
        )
    return schema
def inspect_hc(file_bytes: bytes) -> Dict[str, Any]:
    envelope = _open_outer_envelope(file_bytes)
    schedule = envelope.get("e")
    password_protected = bool(envelope.get("h", 0))
    slots = envelope.get("o", [])
    slot_count = len(slots) if isinstance(slots, list) else 0
    if schedule in ("n2", "n8") and password_protected:
        protection = "hwid+password"
    elif schedule in ("n2", "n8"):
        protection = "hwid"
    elif password_protected:
        protection = "password"
    else:
        protection = "none"
    return {
        "magic": envelope.get("a"),
        "schema": envelope.get("b"),
        "cipher": envelope.get("c"),
        "kdf": envelope.get("d"),
        "key_schedule": schedule,
        "features": envelope.get("f", []),
        "version_code": envelope.get("n"),
        "protection": protection,
        "password_kdf": envelope.get("k") if password_protected else None,
        "password_opslimit": envelope.get("l") if password_protected else None,
        "password_memlimit": envelope.get("m") if password_protected else None,
        "hwid_slot_count": slot_count,
    }
def _feature_string(envelope: Dict[str, Any]) -> str:
    features = envelope.get("f")
    if not isinstance(features, list) or not all(isinstance(item, str) for item in features):
        raise HCDecryptError("envelope feature list is invalid")
    return ",".join(features)
def _normalize_hwid(hwid: str) -> bytes:
    value = hwid.strip()
    if len(value) != 32:
        raise HCDecryptError("HWID must be exactly 32 characters")
    if any(ch not in "0123456789abcdefABCDEFhH" for ch in value):
        raise HCDecryptError("HWID contains unsupported characters")
    return value.upper().encode("ascii")
def _n2_section_material(
    envelope: Dict[str, Any],
    hwid: Optional[str],
    password: Optional[str] = None,
) -> Tuple[bytes, bytes]:
    if hwid is None:
        slots = envelope.get("o", [])
        count = len(slots) if isinstance(slots, list) else 0
        raise HCDecryptError(
            "HWID-protected n2 envelope detected "
            f"({count} encrypted key slot{'s' if count != 1 else ''}); provide --hwid"
        )
    schema = _validate_envelope(envelope)
    try:
        envelope_key = bytes.fromhex(envelope["g"])
    except (KeyError, TypeError, ValueError) as exc:
        raise HCDecryptError("invalid inner envelope key") from exc
    if len(envelope_key) != 32:
        raise HCDecryptError("inner envelope key must be 32 bytes")
    features = _feature_string(envelope).encode("utf-8")
    version_bytes = b"1"
    n_value = envelope.get("n")
    n_bytes: Optional[bytes] = None
    if n_value is not None:
        if isinstance(n_value, bool):
            raise HCDecryptError("invalid envelope n value")
        try:
            n_int = int(n_value)
        except (TypeError, ValueError) as exc:
            raise HCDecryptError("invalid envelope n value") from exc
        if str(n_int) != str(n_value) or n_int < 0:
            raise HCDecryptError("invalid envelope n value")
        n_bytes = str(n_int).encode("ascii")
    hwid_bytes = _normalize_hwid(hwid)
    transcript = (
        b"HCCFG\x00" + PACKAGE + b"\x00" + version_bytes + b"\x00"
        + features + b"\x00"
    )
    if n_bytes is not None:
        transcript += n_bytes + b"\x00"
    transcript += b"hwid\x00" + hwid_bytes + b"\x00" + envelope_key
    transcript_digest = _c0_digest(transcript)
    slot_info = (
        b"app-config|n2|" + PACKAGE + b"|" + version_bytes + b"|" + features
    )
    if n_bytes is not None:
        slot_info += b"|" + n_bytes
    slot_info += b"|hwid|" + hwid_bytes
    h_value = envelope.get("h", 0)
    if h_value not in (0, 1, False, True):
        raise HCDecryptError(f"invalid password-protection flag h={h_value!r}")
    ikm = transcript_digest
    aad_protection = b"|0"
    if bool(h_value):
        if password is None:
            raise HCDecryptError(
                "HWID + password protected .hc file; provide both --hwid and -p/--password"
            )
        kdf_name = envelope.get("k")
        if kdf_name not in ("ARGON2ID13", "a1"):
            raise HCDecryptError(
                f"unsupported password KDF {kdf_name!r}; expected "
                "'ARGON2ID13' or schema-2 alias 'a1'"
            )
        try:
            opslimit = int(envelope["l"])
            memlimit = int(envelope["m"])
        except (KeyError, TypeError, ValueError) as exc:
            raise HCDecryptError("invalid ARGON2ID13 parameters") from exc
        password_key = _argon2id13(
            password.encode("utf-8"),
            envelope_key[:16],
            opslimit,
            memlimit,
            32,
        )
        ikm = transcript_digest + password_key
        aad_protection = (
            b"|1|ARGON2ID13|"
            + str(opslimit).encode("ascii")
            + b"|"
            + str(memlimit).encode("ascii")
        )
    slot_key = _hkdf_sha256(ikm, envelope_key, slot_info)
    aad_base = (
        b"HCCFG|" + str(schema).encode("ascii")
        + b"|XCHACHA20P1305|NATIVE-HKDF-SHA256|n2|"
        + PACKAGE + b"|" + version_bytes + b"|" + features + aad_protection
    )
    if n_bytes is not None:
        aad_base += b"|" + n_bytes
    slots = envelope.get("o", [])
    if not isinstance(slots, list) or not slots:
        raise HCDecryptError("n2 envelope has no HWID key slots")
    for slot in slots:
        if not isinstance(slot, dict):
            continue
        try:
            nonce = bytes.fromhex(slot["a"])
            ciphertext = bytes.fromhex(slot["b"])
        except (KeyError, TypeError, ValueError):
            continue
        try:
            section_key = _xchacha20poly1305_decrypt(
                slot_key, nonce, aad_base + b"\x00w", ciphertext
            )
        except HCDecryptError:
            continue
        if len(section_key) == 32:
            return section_key, aad_base
    if bool(envelope.get("h", 0)):
        raise HCDecryptError(
            "HWID/password combination does not match any authenticated n2 key slot"
        )
    raise HCDecryptError("HWID does not match any authenticated n2 key slot")
def _n7_section_material(
    envelope: Dict[str, Any],
    password: Optional[str] = None,
    hwid: Optional[str] = None,
) -> Tuple[bytes, bytes]:
    schema = _validate_envelope(envelope)
    try:
        envelope_key = bytes.fromhex(envelope["g"])
    except (KeyError, TypeError, ValueError) as exc:
        raise HCDecryptError("invalid inner envelope key") from exc
    if len(envelope_key) != 32:
        raise HCDecryptError("inner envelope key must be 32 bytes")
    version_bytes = b"1"
    features = _feature_string(envelope).encode("ascii")
    n_value = envelope.get("n")
    n_bytes: Optional[bytes] = None
    if n_value is not None:
        if isinstance(n_value, bool):
            raise HCDecryptError("invalid envelope n value")
        try:
            n_int = int(n_value)
        except (TypeError, ValueError) as exc:
            raise HCDecryptError("invalid envelope n value") from exc
        if str(n_int) != str(n_value) or n_int < 0:
            raise HCDecryptError("invalid envelope n value")
        n_bytes = str(n_int).encode("ascii")
    transcript = (
        b"HCCFG\x00"
        + PACKAGE
        + b"\x00"
        + version_bytes
        + b"\x00"
        + features
        + b"\x00"
    )
    if n_bytes is not None:
        transcript += n_bytes + b"\x00"
    transcript += envelope_key
    inner_data = b"\xd3" + C0_SHA256_PREFIX[:32] + transcript
    ikm = hmac.new(N7_HMAC_KEY, inner_data, hashlib.sha256).digest()
    h_value = envelope.get("h", 0)
    if h_value not in (0, 1, False, True):
        raise HCDecryptError(f"invalid password-protection flag h={h_value!r}")
    protected = bool(h_value)
    aad_protection = b"|0"
    if protected:
        if password is None:
            raise HCDecryptError(
                "password-protected .hc file; provide -p/--password"
            )
        kdf_name = envelope.get("k")
        if kdf_name not in ("ARGON2ID13", "a1"):
            raise HCDecryptError(
                f"unsupported password KDF {kdf_name!r}; expected "
                "'ARGON2ID13' or schema alias 'a1'"
            )
        try:
            opslimit = int(envelope["l"])
            memlimit = int(envelope["m"])
        except (KeyError, TypeError, ValueError) as exc:
            raise HCDecryptError("invalid ARGON2ID13 parameters") from exc
        password_key = _argon2id13(
            password.encode("utf-8"),
            envelope_key[:16],
            opslimit,
            memlimit,
            32,
        )
        ikm = ikm + password_key
        aad_protection = (
            b"|1|"
            + b"ARGON2ID13"
            + b"|"
            + str(opslimit).encode("ascii")
            + b"|"
            + str(memlimit).encode("ascii")
        )
    section_info = (
        b"app-config|n7|"
        + PACKAGE
        + b"|"
        + version_bytes
        + b"|"
        + features
    )
    if n_bytes is not None:
        section_info += b"|" + n_bytes
    section_key = _hkdf_sha256(ikm, envelope_key, section_info)
    aad_base = (
        b"HCCFG|"
        + str(schema).encode("ascii")
        + b"|XCHACHA20P1305|NATIVE-HKDF-SHA256|n7|"
        + PACKAGE
        + b"|"
        + version_bytes
        + b"|"
        + features
        + aad_protection
    )
    if n_bytes is not None:
        aad_base += b"|" + n_bytes
    return section_key, aad_base
def _n8_section_material(
    envelope: Dict[str, Any],
    hwid: Optional[str],
    password: Optional[str] = None,
) -> Tuple[bytes, bytes]:
    if hwid is None:
        slots = envelope.get("o", [])
        count = len(slots) if isinstance(slots, list) else 0
        raise HCDecryptError(
            "HWID-protected n8 envelope detected "
            f"({count} encrypted key slot{'s' if count != 1 else ''}); provide --hwid"
        )
    schema = _validate_envelope(envelope)
    try:
        envelope_key = bytes.fromhex(envelope["g"])
    except (KeyError, TypeError, ValueError) as exc:
        raise HCDecryptError("invalid inner envelope key") from exc
    if len(envelope_key) != 32:
        raise HCDecryptError("inner envelope key must be 32 bytes")
    features = _feature_string(envelope).encode("ascii")
    version_bytes = b"1"
    n_value = envelope.get("n")
    n_bytes: Optional[bytes] = None
    if n_value is not None:
        if isinstance(n_value, bool):
            raise HCDecryptError("invalid envelope n value")
        try:
            n_int = int(n_value)
        except (TypeError, ValueError) as exc:
            raise HCDecryptError("invalid envelope n value") from exc
        if str(n_int) != str(n_value) or n_int < 0:
            raise HCDecryptError("invalid envelope n value")
        n_bytes = str(n_int).encode("ascii")
    hwid_bytes = _normalize_hwid(hwid)
    transcript = (
        b"HCCFG\x00" + PACKAGE + b"\x00" + version_bytes + b"\x00"
        + features + b"\x00"
    )
    if n_bytes is not None:
        transcript += n_bytes + b"\x00"
    transcript += b"hwid\x00" + hwid_bytes + b"\x00" + envelope_key
    inner_data = b"\xd3" + C0_SHA256_PREFIX[:32] + transcript
    ikm = hmac.new(N7_HMAC_KEY, inner_data, hashlib.sha256).digest()
    h_value = envelope.get("h", 0)
    if h_value not in (0, 1, False, True):
        raise HCDecryptError(f"invalid password-protection flag h={h_value!r}")
    aad_protection = b"|0"
    if bool(h_value):
        if password is None:
            raise HCDecryptError(
                "HWID + password protected .hc file; provide both --hwid and -p/--password"
            )
        kdf_name = envelope.get("k")
        if kdf_name not in ("ARGON2ID13", "a1"):
            raise HCDecryptError(
                f"unsupported password KDF {kdf_name!r}; expected 'ARGON2ID13' or schema-2 alias 'a1'"
            )
        try:
            opslimit = int(envelope["l"])
            memlimit = int(envelope["m"])
        except (KeyError, TypeError, ValueError) as exc:
            raise HCDecryptError("invalid ARGON2ID13 parameters") from exc
        password_key = _argon2id13(
            password.encode("utf-8"),
            envelope_key[:16],
            opslimit,
            memlimit,
            32,
        )
        ikm = ikm + password_key
        aad_protection = (
            b"|1|ARGON2ID13|"
            + str(opslimit).encode("ascii")
            + b"|"
            + str(memlimit).encode("ascii")
        )
    slot_info = (
        b"app-config|n8|" + PACKAGE + b"|" + version_bytes + b"|" + features
    )
    if n_bytes is not None:
        slot_info += b"|" + n_bytes
    slot_info += b"|hwid|" + hwid_bytes
    slot_key = _hkdf_sha256(ikm, envelope_key, slot_info)
    aad_base = (
        b"HCCFG|" + str(schema).encode("ascii")
        + b"|XCHACHA20P1305|NATIVE-HKDF-SHA256|n8|"
        + PACKAGE + b"|" + version_bytes + b"|" + features + aad_protection
    )
    if n_bytes is not None:
        aad_base += b"|" + n_bytes
    slots = envelope.get("o", [])
    if not isinstance(slots, list) or not slots:
        raise HCDecryptError("n8 envelope has no HWID key slots")
    for slot in slots:
        if not isinstance(slot, dict):
            continue
        try:
            nonce = bytes.fromhex(slot["a"])
            ciphertext = bytes.fromhex(slot["b"])
        except (KeyError, TypeError, ValueError):
            continue
        try:
            section_key = _xchacha20poly1305_decrypt(
                slot_key, nonce, aad_base + b"\x00w", ciphertext
            )
        except HCDecryptError:
            continue
        if len(section_key) == 32:
            return section_key, aad_base
    if bool(envelope.get("h", 0)):
        raise HCDecryptError(
            "HWID/password combination does not match any authenticated n8 key slot"
        )
    raise HCDecryptError("HWID does not match any authenticated n8 key slot")
def _section_material(
    envelope: Dict[str, Any], password: Optional[str] = None, hwid: Optional[str] = None
) -> Tuple[bytes, bytes]:
    if envelope.get("e") == "n2":
        return _n2_section_material(envelope, hwid, password)
    if envelope.get("e") == "n7":
        return _n7_section_material(envelope, password, hwid)
    if envelope.get("e") == "n8":
        return _n8_section_material(envelope, hwid, password)
    schema = _validate_envelope(envelope)
    try:
        envelope_key = bytes.fromhex(envelope["g"])
    except (KeyError, TypeError, ValueError) as exc:
        raise HCDecryptError("invalid inner envelope key") from exc
    if len(envelope_key) != 32:
        raise HCDecryptError("inner envelope key must be 32 bytes")
    version = "1"
    version_bytes = b"1"
    features = _feature_string(envelope).encode("utf-8")
    n_value = envelope.get("n")
    n_bytes: Optional[bytes] = None
    if n_value is not None:
        if isinstance(n_value, bool):
            raise HCDecryptError("invalid envelope n value")
        try:
            n_int = int(n_value)
        except (TypeError, ValueError) as exc:
            raise HCDecryptError("invalid envelope n value") from exc
        if str(n_int) != str(n_value) or n_int < 0:
            raise HCDecryptError("invalid envelope n value")
        n_bytes = str(n_int).encode("ascii")
    transcript = (
        b"HCCFG\x00"
        + PACKAGE
        + b"\x00"
        + version_bytes
        + b"\x00"
        + features
        + b"\x00"
    )
    if n_bytes is not None:
        transcript += n_bytes + b"\x00"
    transcript += envelope_key
    transcript_digest = _c0_digest(transcript)
    h_value = envelope.get("h", 0)
    if h_value not in (0, 1, False, True):
        raise HCDecryptError(f"invalid password-protection flag h={h_value!r}")
    protected = bool(h_value)
    ikm = transcript_digest
    aad_protection = b"|0"
    if protected:
        if password is None:
            raise HCDecryptError(
                "password-protected .hc file; provide -p/--password"
            )
        kdf_name = envelope.get("k")
        if kdf_name not in ("ARGON2ID13", "a1"):
            raise HCDecryptError(
                f"unsupported password KDF {kdf_name!r}; expected "
                "'ARGON2ID13' or schema-2 alias 'a1'"
            )
        try:
            opslimit = int(envelope["l"])
            memlimit = int(envelope["m"])
        except (KeyError, TypeError, ValueError) as exc:
            raise HCDecryptError("invalid ARGON2ID13 parameters") from exc
        password_key = _argon2id13(
            password.encode("utf-8"),
            envelope_key[:16],
            opslimit,
            memlimit,
            32,
        )
        ikm = transcript_digest + password_key
        aad_protection = (
            b"|1|"
            + b"ARGON2ID13"
            + b"|"
            + str(opslimit).encode("ascii")
            + b"|"
            + str(memlimit).encode("ascii")
        )
    section_info = (
        b"app-config|n1|" + PACKAGE + b"|" + version_bytes + b"|" + features
    )
    if n_bytes is not None:
        section_info += b"|" + n_bytes
    section_key = _hkdf_sha256(ikm, envelope_key, section_info)
    aad_base = (
        b"HCCFG|"
        + str(schema).encode("ascii")
        + b"|XCHACHA20P1305|NATIVE-HKDF-SHA256|n1|"
        + PACKAGE
        + b"|"
        + version_bytes
        + b"|"
        + features
        + aad_protection
    )
    if n_bytes is not None:
        aad_base += b"|" + n_bytes
    return section_key, aad_base
def _decrypt_section(section: Dict[str, Any], key: bytes, aad_base: bytes) -> bytes:
    try:
        label = section["a"]
        nonce = bytes.fromhex(section["b"])
        ciphertext_and_tag = bytes.fromhex(section["c"])
    except (KeyError, TypeError, ValueError) as exc:
        raise HCDecryptError("invalid encrypted section") from exc
    if not isinstance(label, str) or not label:
        raise HCDecryptError("section label is invalid")
    aad = aad_base + b"\x00" + label.encode("utf-8")
    return _xchacha20poly1305_decrypt(key, nonce, aad, ciphertext_and_tag)
def _decrypt_profile_sidecar(
    section: Dict[str, Any], key: bytes, aad_base: bytes
) -> Optional[bytes]:
    nested = section.get("d")
    if nested is None:
        return None
    if not isinstance(nested, dict):
        raise HCDecryptError("invalid profile payload sidecar")
    label = section.get("a")
    if not isinstance(label, str) or not label:
        raise HCDecryptError("profile sidecar parent label is invalid")
    try:
        nonce = bytes.fromhex(nested["a"])
        ciphertext_and_tag = bytes.fromhex(nested["b"])
    except (KeyError, TypeError, ValueError) as exc:
        raise HCDecryptError("invalid profile payload sidecar") from exc
    aad = aad_base + b"\x00" + label.encode("utf-8") + b":x"
    return _xchacha20poly1305_decrypt(key, nonce, aad, ciphertext_and_tag)
def _decrypt_hpr1(
    container: bytes, key: bytes, aad_base: bytes, label: Optional[str]
) -> bytes:
    if not container.startswith(b"HPR1") or len(container) < 44:
        return container
    nonce = container[4:28]
    ciphertext_and_tag = container[28:]
    tag = label if label else "s0"
    aad = aad_base + b"\x00" + tag.encode("utf-8") + b":r"
    try:
        return _xchacha20poly1305_decrypt(key, nonce, aad, ciphertext_and_tag)
    except Exception:
        subkey = _hchacha20(key, nonce[:16])
        nonce12 = b"\x00\x00\x00\x00" + nonce[16:]
        return _stream_xor(ciphertext_and_tag[:-16], subkey, nonce12, 1)
class _HPC1Reader:
    def __init__(self, data: bytes):
        self.data = data
        self.offset = 0
    def take(self, size: int) -> bytes:
        if size < 0 or self.offset + size > len(self.data):
            raise HCDecryptError("truncated HPC1 record")
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
            raise HCDecryptError("implausible HPC1 string length")
        return self.take(size).decode("utf-8")
def parse_hpc1(data: bytes, label: Optional[str] = None) -> Dict[str, Any]:
    reader = _HPC1Reader(data)
    if reader.take(4) != b"HPC1":
        raise HCDecryptError("section is not an HPC1 record")
    field_count = reader.u32()
    if field_count != 11:
        raise HCDecryptError(f"unsupported HPC1 field count: {field_count}")
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
        raise HCDecryptError("trailing bytes after HPC1 record")
    try:
        options: Any = json.loads(options_text) if options_text else {}
    except json.JSONDecodeError:
        options = options_text
    result: Dict[str, Any] = {
        "format": "HPC1",
        "field_count": field_count,
        "name": name,
        "protocol": protocol,
        "host": host,
        "port": port,
        "server_address": (
            options.get("serverAddress").strip()
            if isinstance(options, dict) and isinstance(options.get("serverAddress"), str)
            else f"{host}:{port}"
        ),
        "username": username,
        "password": password,
        "payload": payload,
        "options": options,
        "flags": flags,
        "updated_at_ms": updated_at_ms,
        "mode": mode,
    }
    if label is not None:
        result["label"] = label
    return result
def _section_list(value: Any) -> List[Dict[str, Any]]:
    if isinstance(value, list) and all(isinstance(item, dict) for item in value):
        return value
    if isinstance(value, dict) and all(isinstance(item, dict) for item in value.values()):
        return list(value.values())
    raise HCDecryptError("envelope profile-section collection is invalid")
def _decrypt_parts(
    file_bytes: bytes, password: Optional[str] = None, hwid: Optional[str] = None
) -> Tuple[
    Dict[str, Any],
    bytes,
    List[Tuple[Optional[str], bytes, Optional[bytes]]],
]:
    envelope = _open_outer_envelope(file_bytes)
    section_key, aad_base = _section_material(envelope, password, hwid)
    main_section = envelope.get("i")
    if not isinstance(main_section, dict):
        raise HCDecryptError("main section is missing")
    main_plaintext = _decrypt_section(main_section, section_key, aad_base)
    sections: List[Tuple[Optional[str], bytes, Optional[bytes]]] = []
    for section in _section_list(envelope.get("j", [])):
        plaintext = _decrypt_section(section, section_key, aad_base)
        label = section.get("a")
        if plaintext.startswith(b"HPR1"):
            plaintext = _decrypt_hpr1(plaintext, section_key, aad_base, label)
        sidecar = _decrypt_profile_sidecar(section, section_key, aad_base)
        sections.append((label, plaintext, sidecar))
    return envelope, main_plaintext, sections
PROTECTION_KEY_MAP = {
    "a": "accessMode",
    "c": "expiryEnabled",
    "f": "hwidLockEnabled",
    "g": "hwids",
    "h": "loginHwidEnabled",
    "l": "mobileDataOnly",
    "m": "blockRoot",
    "o": "providerLockEnabled",
    "p": "providerCodes",
    "v": "note",
}
def _normalize_protection_keys(protections: Any) -> Any:
    if not isinstance(protections, dict):
        return protections
    return {PROTECTION_KEY_MAP.get(key, key): value for key, value in protections.items()}
def decrypt_hc(
    file_bytes: bytes,
    password: Optional[str] = None,
    hwid: Optional[str] = None,
) -> Dict[str, Any]:
    envelope, main_plaintext, sections = _decrypt_parts(file_bytes, password, hwid)
    try:
        main_config = json.loads(main_plaintext.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise HCDecryptError("main section is not valid UTF-8 JSON") from exc
    profiles: List[Dict[str, Any]] = []
    other_sections: List[Dict[str, Any]] = []
    for label, plaintext, sidecar in sections:
        if plaintext.startswith(b"HPC1"):
            profile = parse_hpc1(plaintext, label=label)
            if sidecar is not None:
                try:
                    profile["custom_payload_sidecar"] = sidecar.decode("utf-8")
                except UnicodeDecodeError:
                    profile["custom_payload_sidecar_hex"] = sidecar.hex()
            profiles.append(profile)
            continue
        try:
            decoded: Any = plaintext.decode("utf-8")
            if decoded.startswith(("{", "[")):
                decoded = json.loads(decoded)
        except (UnicodeDecodeError, json.JSONDecodeError):
            decoded = {"hex": plaintext.hex()}
        other_sections.append({"label": label, "content": decoded})
    return {
        "format": {
            "magic": envelope["a"],
            "schema": envelope["b"],
            "cipher": envelope["c"],
            "kdf": envelope["d"],
            "key_schedule": envelope["e"],
            "features": envelope["f"],
            "version_code": envelope.get("n"),
            "password_protected": bool(envelope.get("h", 0)),
            "password_kdf": envelope.get("k") if envelope.get("h", 0) else None,
        },
        "protections": main_config.get("g", {}) if isinstance(main_config, dict) else {},
        "main_config": main_config,
        "profiles": profiles,
        "other_sections": other_sections,
    }
def decrypt_hc_v79(
    file_bytes: bytes,
    password: Optional[str] = None,
    hwid: Optional[str] = None,
) -> Dict[str, Any]:
    data = decrypt_hc(file_bytes, password=password, hwid=hwid)
    clean_config: List[Dict[str, Any]] = []
    for profile in data.get("profiles", []):
        clean_profile: Dict[str, Any] = {
            "name": profile.get("name", ""),
            "protocol": profile.get("protocol", ""),
            "host": profile.get("host", ""),
            "port": profile.get("port", 0),
            "username": profile.get("username", ""),
            "password": profile.get("password", ""),
            "mode": profile.get("mode", ""),
        }
        options = profile.get("options", {})
        if isinstance(options, dict):
            for key, value in options.items():
                clean_profile[key] = value
        if profile.get("payload"):
            clean_profile["payload"] = profile.get("payload")
        if "custom_payload_sidecar" in profile:
            clean_profile["custom_payload_sidecar"] = profile["custom_payload_sidecar"]
        if "custom_payload_sidecar_hex" in profile:
            clean_profile["custom_payload_sidecar_hex"] = profile["custom_payload_sidecar_hex"]
        clean_config.append(clean_profile)
    result: Dict[str, Any] = {
        "config": clean_config,
        "protections": _normalize_protection_keys(data.get("protections", {})),
    }
    if data.get("other_sections"):
        result["other_sections"] = data["other_sections"]
    return result
class HabibiFinalSSH:
    def __init__(self):
        self.KEY_1 = binascii.unhexlify("2be4342943c6f91ff58987f41a1aafd179eeb4e053f5cea55b11d6a7db58bd7d")
        self.KEY_2 = binascii.unhexlify("3380aa278b744ba5b529a7f32fa803e48749280dae378345d9b526cf1dbce372")
        self.KEY_3 = binascii.unhexlify("cea9305c95168b162a335b137c61983b8df54e6375da01136547890f14c5fac3")
        self.KEY_4 = binascii.unhexlify("4beeace0e42bae8f29470cf40cf2dfacd5f4e1f751912bf52e803c8c85792193")
        self.KEY_5 = binascii.unhexlify("f8e5f6ebea90558eb32229da24fd0fb7d813091dafe89bb2954fda33b4c60f63")
        self.KEY_6 = binascii.unhexlify("81342f558a6273bac4548d473f54c4ffc7c41747dee81369acab9c787d41ab9c")
        self.KEY_7 = binascii.unhexlify("45635e6fc70486e2fd10d3c2b4780f02d0b4c5f4aa929fc54f86bb8fa4417944")
        self.KEY_8 = binascii.unhexlify("3d632a251c9820f2baf83e15498d27548fc67921cb437f8ce48505989378adea")
        self.ALL_KEYS = { "K1": self.KEY_1, "K2": self.KEY_2, "K3": self.KEY_3, "K4": self.KEY_4, "K5": self.KEY_5, "K6": self.KEY_6, "K7": self.KEY_7, "K8": self.KEY_8 }
        self.RST_KEYS = {
            0: b"JN1k3YHc2.6_v235", 1: b"JN1k3YHc_2.7_v71", 2: b"JN1k3YHc2.7.ps69",
            3: b"JN1k3YHc2.7.6950", 4: b"Jn1K3yHc2.8.ps08", 5: b"Jn1K3yHc2.9.ps6c",
            6: b"Zk:L7>WKaiK*s9>D", 7: b"!<f!&WIlM**R.B0X", 8: b"b4a5opinx2uloec6"
        }
        self.JKL_KEY_OLD = bytes([0xd5, 0xd4, 0xd3, 0xd2, 0xd1, 0xd0, 0xcf, 0xce, 0xcd, 0xcc, 0xbd, 0xbc, 0xbb, 0xba, 0xb9, 0xb8, 0xb7, 0xb6, 0xb5, 0xb4])
        self.JKL_KEY_NEW = bytes([8, 9, 10, 11, 12, 13, 14, 15, 17, 17, 5, 4, 3, 2, 1, 0, 255, 254, 253, 252])
        self.token_map = {
            0: "payload", 1: "proxy", 2: "lockAllConfig", 3: "blockedByRoot", 4: "expiryTime", 5: "noteEnabled", 6: "notes",
            7: "sshField", 8: "mobileDataAndLockProvider", 9: "unlockUserAndPass", 10: "ovpnConfig", 11: "ovpnUserAndPass",
            12: "sni", 13: "unlockUserAndPass2", 14: "unknown14", 15: "blockedByHwid", 16: "cloudconfig", 17: "psiphon",
            18: "name", 19: "blockArea", 20: "connectionMode", 21: "blockedByPassword", 22: "unknown22", 23: "extraSniffer",
            24: "psiphon2", 25: "v2rayEnabled", 26: "v2rayConfig", 27: "version", 28: "slowdnsEnabled", 29: "slowdnsServer",
            30: "slowdnsPublickey", 31: "dnsResolver"
        }
    def calculate_iv(self, s):
        if not s: return 0
        matches = re.findall(r'(-?\d+)\.(-?\d+)', s)
        return len(matches)
    def extract_z3a(self, data, iv):
        if not data: return ""
        new_data = ""
        matches = re.findall(r'(-?\d+)\.(-?\d+)', data)
        for m in matches:
            val1, val2 = int(m[0]), int(m[1])
            val11, val22 = val1 - iv, val2 - iv
            try:
                divisor = math.pow(2, val22)
                if divisor == 0: continue
                val3 = math.floor(val11 / divisor) % 256
                if val3 < 0: val3 += 256
                new_data += chr(int(val3))
            except: continue
        return new_data
    def decrypt_braille(self, ciphertext):
        secret_alphabet = "⠁⠃⠉⠙⠑⠋⠛⠓⠊⠚⠅⠇⠍⠝⠕⠏⠟⠗⠎⠞⠥⠧⠺⠭⠽⠵⠼⠁⠼⠃⠼⠉⠼⠙⠼⠑⠼⠋⠼⠛⠼⠓⠼⠊⠼⠚"
        decrypted_bytes = bytearray()
        try:
            for i in range(len(ciphertext) // 2):
                char1, char2 = ciphertext[i * 2], ciphertext[i * 2 + 1]
                val1 = secret_alphabet.index(char1) * 16
                val2 = secret_alphabet.index(char2)
                decrypted_bytes.append((val1 + val2) & 255)
            return decrypted_bytes.decode('utf-8')
        except ValueError:
            return ciphertext
    def process_ssh_field(self, raw_val):
        if not raw_val: return raw_val
        if len(raw_val) > 0 and raw_val[0] in "⠁⠃⠉⠙⠑⠋⠛⠓⠊⠚⠅⠇⠍⠝⠕⠏⠟⠗⠎⠞⠥⠧⠺⠭⠽⠵⠼":
            raw_val = self.decrypt_braille(raw_val)
        normal_ssh_pattern = r'^([\w\.-]+):([\d\-]+)@(.+):(.+)$'
        match = re.match(normal_ssh_pattern, raw_val)
        if match:
            host, port, u_enc, p_enc = match.groups()
            u_iv = self.calculate_iv(u_enc)
            u_dec = self.extract_z3a(u_enc, u_iv)
            final_user = u_dec if u_dec else u_enc
            p_iv = self.calculate_iv(p_enc)
            p_dec = self.extract_z3a(p_enc, p_iv)
            final_pass = p_dec if p_dec else p_enc
            return f"{host}:{port}@{final_user}:{final_pass}"
        at_idx = raw_val.rfind("@")
        if at_idx != -1:
            host_part, rest = raw_val[:at_idx + 1], raw_val[at_idx + 1:]
            colon = rest.find(":")
            if colon != -1:
                u_enc, p_enc = rest[:colon], rest[colon + 1:]
                u_dec = self.extract_z3a(u_enc, self.calculate_iv(u_enc))
                p_dec = self.extract_z3a(p_enc, self.calculate_iv(p_enc))
                final_user = u_dec if u_dec else u_enc
                final_pass = p_dec if p_dec else p_enc
                candidate = f"{host_part}{final_user}:{final_pass}"
                if candidate != raw_val:
                    return candidate
        return raw_val
    def process_ovpn_credentials(self, raw_val):
        if not raw_val: return raw_val
        parts = raw_val.split(':', 1)
        if len(parts) == 2:
            u_enc, p_enc = parts[0], parts[1]
            u_iv = self.calculate_iv(u_enc)
            u_dec = self.extract_z3a(u_enc, u_iv)
            final_user = u_dec if u_dec else u_enc
            p_iv = self.calculate_iv(p_enc)
            p_dec = self.extract_z3a(p_enc, p_iv)
            final_pass = p_dec if p_dec else p_enc
            return f"{final_user}:{final_pass}"
        return raw_val
    def clean_hex(self, raw_str):
        clean = re.sub(r'[^0-9a-fA-F]', '', str(raw_str))
        if len(clean) % 2 != 0: clean = "0" + clean
        return clean
    def is_hex(self, s):
        return bool(s and len(s) >= 16 and re.fullmatch(r'^[0-9a-fA-F]+$', s))
    def is_mostly_printable(self, s, strict=False):
        if not s: return False
        if len(s) < 4: return True
        printable = sum(1 for c in s if c in '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!"#$%&\'()*+,-./:;<=>?@[\\]^_`{|}~ \t\n\r')
        ratio = printable / len(s)
        return ratio > 0.90 if strict else ratio > 0.80
    def abc_decrypt(self, raw_input, key, nonce_override=None):
        try:
            data = binascii.unhexlify(self.clean_hex(raw_input))
            if len(data) <= 16: return ""
            cipher = ChaCha20.new(key=key, nonce=nonce_override if nonce_override else b'\xdb' * 8)
            cipher.seek(64)
            dec = cipher.decrypt(data[:-16])
            try: return dec.decode('utf-8')
            except: return dec.decode('latin-1')
        except: return ""
    def rst_decrypt(self, encrypted_str):
        try:
            b64_string = bytearray([c ^ bytes(range(2, 22))[i % 20] for i, c in enumerate(encrypted_str.encode('utf-8'))])
            aes_ciphertext = base64.b64decode(b64_string)
            for aes_key in self.RST_KEYS.values():
                try:
                    dec = unpad(AES.new(aes_key, AES.MODE_ECB).decrypt(aes_ciphertext), AES.block_size).decode('utf-8', errors='ignore')
                    if "[splitConfig]" in dec: return dec
                except: pass
        except: pass
        return None
    def jkl_decrypt(self, input_string, is_new_format=False):
        if not input_string: return input_string
        try:
            pad = len(input_string) % 4
            data = bytearray(base64.b64decode(input_string + "=" * (4 - pad) if pad else input_string, validate=True))
            active_key = self.JKL_KEY_NEW if is_new_format else self.JKL_KEY_OLD
            for i in range(len(data)):
                k, d = active_key[i % 20], data[i]
                data[i] = (((d ^ 0xff) & 0xca) | (d & 0x35)) ^ (((k ^ 0xff) & 0xca) | (k & 0x35))
            return base64.b64decode(data.decode('utf-8'), validate=True).decode('utf-8')
        except: return input_string
    def decrypt_field(self, token, dynamic_nonce):
        if not token or token in ["true", "false", "lifeTime", "[splitPsiphon][splitPsiphon]"] or token.startswith("<"):
            return token
        candidates = []
        clean_h = self.clean_hex(token)
        if len(clean_h) >= 32 and self.is_hex(clean_h):
            try: candidates.append(binascii.unhexlify(clean_h))
            except: pass
        if len(token) > 16:
            try: candidates.append(token.encode('latin-1'))
            except: pass
            try: candidates.append(token.encode('utf-8'))
            except: pass
        for data_bytes in list(dict.fromkeys(candidates)):
            if len(data_bytes) <= 16: continue
            for chacha_key in self.ALL_KEYS.values():
                try:
                    cipher = ChaCha20.new(key=chacha_key, nonce=dynamic_nonce)
                    cipher.seek(64)
                    dec = cipher.decrypt(data_bytes[:-16])
                    try: dec_str = dec.decode('utf-8')
                    except: dec_str = dec.decode('latin-1')
                    for jkey in [self.JKL_KEY_NEW, self.JKL_KEY_OLD]:
                        final_out = self.jkl_decrypt(dec_str, is_new_format=(jkey == self.JKL_KEY_NEW))
                        if final_out and final_out != dec_str and self.is_mostly_printable(final_out):
                            return final_out
                    if self.is_mostly_printable(dec_str, strict=True):
                        if any(x in dec_str for x in ["HTTP", "@", ":", "{"]) or dec_str.isalnum(): return dec_str
                except: pass
        for jkey in [self.JKL_KEY_NEW, self.JKL_KEY_OLD]:
            out = self.jkl_decrypt(token, is_new_format=(jkey == self.JKL_KEY_NEW))
            if out != token and self.is_mostly_printable(out): return out
        return token
    def process(self, initial_ciphertext):
        try:
            outer = self.abc_decrypt(initial_ciphertext, self.KEY_6)
            if not outer or not outer.startswith("{"): return None
            json_obj = json.loads(outer)
            cfg_obj = json_obj.get("cfg", {})
            is_new_format = "content" in cfg_obj
            meta_values, protections = {}, {}
            if is_new_format:
                for k, name in {'b': 'hwid', 'f': 'area'}.items():
                    val = str(json_obj.get(k) or cfg_obj.get(k) or "")
                    if val: meta_values[name] = val; protections[name] = val
                target_cipher, split_delim = cfg_obj.get('content'), "[splitConfig]"
            else:
                obj_a = json_obj.get('a', {})
                for k, name in {'bb': 'hwid', 'e': 'password', 'fe': 'area', 'ed': 'provider'}.items():
                    val = json_obj.get(k) if k == 'e' else obj_a.get(k)
                    if val:
                        dec_val = self.abc_decrypt(str(val), self.KEY_8)
                        meta_values[name] = dec_val
                        if dec_val: protections[name] = dec_val
                target_cipher = json_obj.get('xy') or obj_a.get('xy')
                split_delim = str(json_obj.get('uv') or obj_a.get('uv'))
            if not target_cipher or not split_delim: return None
            h, p, pr, a = meta_values.get('hwid'), meta_values.get('password'), meta_values.get('provider'), meta_values.get('area')
            def to_hex(s): return binascii.hexlify(s.encode()).decode().lower() if s else ""
            derived_hex = to_hex(h) + to_hex(h) if h and not any([p, pr, a]) else to_hex(p) + to_hex(h) + to_hex(pr) + to_hex(a)
            nonce_list = [0xdb] * 8
            if derived_hex:
                try:
                    d_bytes = binascii.unhexlify(derived_hex)
                    for i in range(min(len(d_bytes), 8)): nonce_list[i] = d_bytes[i]
                except: pass
            xy_dec = self.rst_decrypt(str(target_cipher)) if is_new_format else None
            if not xy_dec:
                for chacha_key in self.ALL_KEYS.values():
                    temp_dec = self.abc_decrypt(str(target_cipher), chacha_key)
                    if temp_dec and split_delim in temp_dec:
                        xy_dec = temp_dec
                        break
            if not xy_dec: return None
            config_data = {}
            for i, token in enumerate(xy_dec.split(split_delim)):
                if i in (22, 24) or not token: continue
                out = token
                if not is_new_format:
                    if self.is_hex(token): out = self.abc_decrypt(token, self.KEY_8, bytes(nonce_list))
                    out = self.jkl_decrypt(out, False)
                else:
                    out = self.decrypt_field(token, bytes(nonce_list))
                if i == 7 and out: out = self.process_ssh_field(out)
                elif i == 11 and out: out = self.process_ovpn_credentials(out)
                if isinstance(out, str) and (out.startswith("{") or out.startswith("[")):
                    try: out = json.loads(out)
                    except: pass
                if not (isinstance(out, str) and self.is_hex(out)) and out != "":
                    config_data[self.token_map.get(i, f"field_{i}")] = out
            return {"config": [config_data], "protections": protections}
        except:
            return None
def decrypt_legacy_hc(file_bytes: bytes) -> Optional[Dict[str, Any]]:
    if not CRYPTO_AVAILABLE: return None
    key_bytes = bytes.fromhex("e382e4b8adc386f09f9293")
    for candidate in _carrier_candidates(file_bytes):
        variants = [candidate]
        try:
            variants.append(candidate.decode('utf-8', errors='ignore').encode('latin-1', errors='ignore'))
        except Exception:
            pass
        for encrypted_data in variants:
            decrypted_data = bytearray(b ^ key_bytes[i % len(key_bytes)] for i, b in enumerate(encrypted_data))
            try: res = HabibiFinalSSH().process(decrypted_data.decode('utf-8'))
            except Exception: res = None
            if res:
                return res
    return None
V4_PACKAGE = b"xyz.easypro.httpcustom"
V4_OUTER_SEED = b"hc-envelope-seal-v4 xyz.easypro.httpcustom"
V4_OUTER_SALT = b"hc-envelope-seal-salt-v4"
V4_OUTER_INFO = b"hc-envelope-seal-info-v4"
V4_OUTER_AAD = b"HCX4|xyz.easypro.httpcustom|1"
V4_CERT_DIGEST = bytes.fromhex(
    "95dd433d7e4a0be02d55cc62553edcfc8f077fe780be5a7da7f861c2558dc181"
)
V4_IPAD_STATE = [0x82515A9A, 0xF6EC05FC, 0xF650B6CD, 0x523F8CE6,
                 0xEDF419EC, 0x1D6D6573, 0x66FF1B89, 0xF40A0181]
V4_OPAD_STATE = [0x82185B01, 0x35CB48BE, 0xDB6C3846, 0xBD714EC5,
                 0x627728AF, 0xDBAAE4DB, 0x463FBF8D, 0x88A24381]
V4_VERSION_LABEL = "7.11.28 (899)"
N15_IPAD_STATE = [0xAABD3A1E, 0x3D63A211, 0xE615B378, 0x46A07517,
                  0x11F5CAB4, 0xA7AEF829, 0x83C7543B, 0x2D971AB7]
N15_OPAD_STATE = [0x423FCB79, 0xC4DD3DC8, 0x57D814AC, 0x1660ED59,
                  0xDBB328B7, 0xCC389261, 0x06F1803E, 0xE3130C6B]
V4_VERSION_LABEL_934 = "8.0.22 (934)"
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
PROTECTION_KEY_MAP.update({
    "d": "expiryTime",
    "e": "noteEnabled",
    "j": "loginHwidAuthorizationRequired",
})
def _ror32_v4(x: int, n: int) -> int:
    return ((x >> n) | (x << (32 - n))) & 0xFFFFFFFF
def _sha256_compress_v4(state, block: bytes):
    if len(block) != 64:
        raise HCDecryptError("internal V4 SHA-256 block must be 64 bytes")
    w = list(struct.unpack(">16I", block)) + [0] * 48
    for i in range(16, 64):
        x, y = w[i - 15], w[i - 2]
        s0 = _ror32_v4(x, 7) ^ _ror32_v4(x, 18) ^ (x >> 3)
        s1 = _ror32_v4(y, 17) ^ _ror32_v4(y, 19) ^ (y >> 10)
        w[i] = (w[i - 16] + s0 + w[i - 7] + s1) & 0xFFFFFFFF
    a, b, c, d, e, f, g, h = state
    for i in range(64):
        s1 = _ror32_v4(e, 6) ^ _ror32_v4(e, 11) ^ _ror32_v4(e, 25)
        ch = (e & f) ^ ((~e) & g)
        t1 = (h + s1 + ch + V4_SHA256_K[i] + w[i]) & 0xFFFFFFFF
        s0 = _ror32_v4(a, 2) ^ _ror32_v4(a, 13) ^ _ror32_v4(a, 22)
        maj = (a & b) ^ (a & c) ^ (b & c)
        t2 = (s0 + maj) & 0xFFFFFFFF
        h, g, f, e, d, c, b, a = g, f, e, (d + t1) & 0xFFFFFFFF, c, b, a, (t1 + t2) & 0xFFFFFFFF
    return [(x + y) & 0xFFFFFFFF for x, y in zip(state, [a, b, c, d, e, f, g, h])]
def _finish_hmac_state_v4(state, data: bytes) -> bytes:
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
def _derive_n15(salt: bytes, aad: bytes, password_key: bytes = b"") -> bytes:
    inner = _finish_hmac_state_v4(N15_IPAD_STATE, b"\xf1" + V4_CERT_DIGEST + aad)
    outer = _finish_hmac_state_v4(N15_OPAD_STATE, inner)
    return _hkdf_sha256(outer + password_key, salt, b"hc-config-content-v12")
def _hkdf_layer(key: bytes, info_label: bytes, section_aad: bytes) -> bytes:
    return _hkdf_sha256(key, info_label, section_aad)
def _v4_outer_key() -> bytes:
    return _hkdf_sha256(_c0_v4(V4_OUTER_SEED), V4_OUTER_SALT, V4_OUTER_INFO)
def _v4_logical_bytes(raw: bytes) -> bytes:
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise HCDecryptError("V4 file is not in UTF-8 byte-carrier format") from exc
    if any(ord(ch) > 255 for ch in text):
        raise HCDecryptError("V4 file contains non-byte Unicode characters")
    return bytes(ord(ch) for ch in text)
def _open_outer_v4(file_bytes: bytes) -> Dict[str, Any]:
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
                    if (b == 10 and str(env.get("e")) in ("n11", "n12")) or (
                        b == 12 and str(env.get("e")) == "n15"
                    ):
                        return env
                    if b == 9:
                        raise HCDecryptError("ACCESS_ID_PRIVATE_KEY_REQUIRED: recipient wrapper")
                    if b == 12 and str(env.get("e")) == "n16":
                        raise HCDecryptError("UNSUPPORTED_HWID_SCHEDULE_N16: supplied credentials are not disproved")
                    if b in (11, 13) or str(env.get("e")) == "n13" or "p" in env:
                        raise HCDecryptError(
                            "V4 Extra Protection requires the original app's "
                            "online activation + device-security check"
                        )
                    raise HCDecryptError(
                        f"unsupported V4 schema/schedule: schema={env.get('b')!r}, "
                        f"schedule={env.get('e')!r}"
                    )
                raise HCDecryptError("unexpected V4 outer envelope magic")
            except HCDecryptError as exc:
                if any(marker in str(exc) for marker in ("Extra Protection", "unsupported V4", "ACCESS_ID_PRIVATE_KEY_REQUIRED", "UNSUPPORTED_HWID_SCHEDULE_N16")):
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
    raise HCDecryptError(f"not a V4 .hc outer envelope ({last_error})")
def _v4_norm_hwid(hwid: str) -> bytes:
    cleaned = re.sub(r"[^0-9A-Za-z]", "", str(hwid))
    if len(cleaned) != 32 or any(c not in "0123456789abcdefABCDEFhH" for c in cleaned):
        raise HCDecryptError("V4 HWID must normalize to 32 hexadecimal characters")
    return cleaned.upper().encode()
def _validate_envelope_v4(env: Dict[str, Any]):
    schema = int(env.get("b", 0))
    sched = env.get("e")
    if schema in (11, 13) or sched == "n13" or "p" in env:
        raise HCDecryptError(
            "V4 Extra Protection (schema n13) requires the app's online "
            "activation + device-security check"
        )
    if not ((schema == 10 and sched in ("n11", "n12"))
            or (schema == 12 and sched == "n15")):
        raise HCDecryptError(
            f"unsupported V4 schema/schedule: schema={schema}, schedule={sched!r}"
        )
    hflag = env.get("h", 0)
    if hflag not in (0, 1, False, True):
        raise HCDecryptError(f"unsupported V4 password flag: {hflag!r}")
    try:
        ekey = bytes.fromhex(env["g"])
    except (KeyError, TypeError, ValueError) as exc:
        raise HCDecryptError("invalid V4 envelope key/salt") from exc
    if len(ekey) != 32:
        raise HCDecryptError("invalid V4 envelope key/salt length")
    return schema, sched, ekey
def _transcript_v4(env: Dict[str, Any], ekey: bytes, hwid: Optional[str] = None) -> bytes:
    features = ",".join(env.get("f", [])).encode()
    transcript = b"HCCFG\x00" + V4_PACKAGE + b"\x00" + b"1\x00" + features + b"\x00"
    if env.get("n") is not None:
        n = int(env["n"])
        if n < 0:
            raise HCDecryptError("invalid V4 reader version")
        transcript += str(n).encode() + b"\x00"
    if hwid is not None:
        transcript += b"hwid\x00" + _v4_norm_hwid(hwid) + b"\x00"
    transcript += ekey
    return transcript
def _info_v4(env: Dict[str, Any], hwid: Optional[str] = None) -> bytes:
    features = ",".join(env.get("f", [])).encode()
    info = b"app-config|" + str(env["e"]).encode() + b"|" + V4_PACKAGE + b"|1|" + features
    if env.get("n") is not None:
        info += b"|" + str(int(env["n"])).encode()
    if hwid is not None:
        info += b"|hwid|" + _v4_norm_hwid(hwid)
    return info
def _aad_base_v4(env: Dict[str, Any], password_protected: bool = False) -> bytes:
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
            raise HCDecryptError("V4 password KDF parameters are missing") from exc
        kdf_name = b"ARGON2ID13" if env.get("k") == "a1" else str(env.get("k")).encode()
        aad += b"|1|" + kdf_name + b"|" + str(ops).encode() + b"|" + str(mem).encode()
    else:
        aad += b"|0"
    if env.get("n") is not None:
        aad += b"|" + str(int(env["n"])).encode()
    return aad
def _v4_section_material(
    env: Dict[str, Any], password: Optional[str] = None, hwid: Optional[str] = None
):
    schema, sched, ekey = _validate_envelope_v4(env)
    protected = bool(env.get("h", 0))
    is_hwid = sched == "n12"
    if is_hwid and hwid is None and protected:
        raise HCDecryptError(
            "V4 HWID + password protected .hc file; provide both --hwid and -p/--password"
        )
    if protected and password is None:
        raise HCDecryptError("password-protected V4 .hc file; provide -p/--password")
    if is_hwid and hwid is None:
        raise HCDecryptError("HWID-protected V4 .hc file; provide --hwid")
    transcript = _transcript_v4(env, ekey, hwid if is_hwid else None)
    info = _info_v4(env, hwid if is_hwid else None)
    aad_base = _aad_base_v4(env, password_protected=protected)
    if schema == 12:
        password_key = b""
        if protected:
            try:
                ops, mem = int(env["l"]), int(env["m"])
            except (KeyError, TypeError, ValueError) as exc:
                raise HCDecryptError("V4 password KDF parameters are invalid") from exc
            if not (1 <= ops <= 10 and 8192 <= mem <= 256 * 1024 * 1024):
                raise HCDecryptError("V4 password KDF resource limit exceeded")
            password_key = _argon2id13(password.encode("utf-8"), ekey[:16], ops, mem)
        contact_key = _derive_n15(ekey, aad_base, password_key)
        return contact_key, aad_base, schema
    ikm = _c0_v4(transcript)
    if protected:
        try:
            ops, mem = int(env["l"]), int(env["m"])
        except (KeyError, TypeError, ValueError) as exc:
            raise HCDecryptError("V4 password KDF parameters are invalid") from exc
        ikm += _argon2id13(password.encode("utf-8"), ekey[:16], ops, mem)
    base_key = _hkdf_sha256(ikm, ekey, info)
    section_key = base_key
    if is_hwid:
        slots = env.get("o")
        if not isinstance(slots, list) or not slots:
            raise HCDecryptError("V4 HWID schedule has no key slots")
        slot_found = False
        for slot in slots:
            try:
                candidate = _xchacha20poly1305_decrypt(
                    base_key,
                    bytes.fromhex(slot["a"]),
                    aad_base + b"\x00w",
                    bytes.fromhex(slot["b"]),
                )
                if len(candidate) == 32:
                    section_key = candidate
                    slot_found = True
                    break
            except (KeyError, TypeError, ValueError, HCDecryptError):
                continue
        if not slot_found:
            raise HCDecryptError("HWID does not match any authenticated V4 key slot")
    return section_key, aad_base, schema
def _decrypt_parts_v4(
    file_bytes: bytes, password: Optional[str] = None, hwid: Optional[str] = None
):
    env = _open_outer_v4(file_bytes)
    contact_key, aad_base, schema = _v4_section_material(
        env, password=password, hwid=hwid
    )
    def open_section(key: bytes, label: str, alg: str, nonce_hex: str, ct_hex: str) -> bytes:
        section_aad = aad_base + b"\x00" + label.encode("utf-8")
        if schema == 12:
            key = _hkdf_layer(key, b"hc-config-part-v12", section_aad)
        return _xchacha20poly1305_decrypt(
            key, bytes.fromhex(nonce_hex), section_aad, bytes.fromhex(ct_hex)
        )
    main_section = env.get("i")
    if not isinstance(main_section, dict):
        raise HCDecryptError("V4 main section is missing")
    try:
        main_plaintext = open_section(
            contact_key, "m", main_section.get("a", "m"),
            main_section["b"], main_section["c"],
        )
    except HCDecryptError as exc:
        if "authentication failed" in str(exc).lower():
            raise HCDecryptError(
                "V4 authentication failed: wrong password/HWID for this .hc file"
            ) from exc
        raise
    sections = []
    raw_sections = env.get("j", [])
    if isinstance(raw_sections, dict):
        raw_sections = list(raw_sections.values())
    if not isinstance(raw_sections, list):
        raise HCDecryptError("V4 envelope profile-section collection is invalid")
    for section in raw_sections:
        if not isinstance(section, dict):
            raise HCDecryptError("V4 envelope profile-section collection is invalid")
        label = section.get("a")
        if not isinstance(label, str) or not label:
            raise HCDecryptError("V4 section label is invalid")
        try:
            plaintext = open_section(
                contact_key, label, section.get("a", label),
                section["b"], section["c"],
            )
        except HCDecryptError as exc:
            if "authentication failed" in str(exc).lower():
                raise HCDecryptError(
                    "V4 authentication failed: wrong password/HWID for this .hc file"
                ) from exc
            raise
        sidecar = None
        nested = section.get("d")
        if nested is not None:
            if not isinstance(nested, dict):
                raise HCDecryptError("invalid V4 profile payload sidecar")
            sidecar_aad = aad_base + b"\x00" + label.encode("utf-8") + b":x"
            sidecar_key = (
                _hkdf_layer(contact_key, b"hc-config-part-v12", sidecar_aad)
                if schema == 12 else contact_key
            )
            sidecar = _xchacha20poly1305_decrypt(
                sidecar_key,
                bytes.fromhex(nested["a"]),
                sidecar_aad,
                bytes.fromhex(nested["b"]),
            )
        if plaintext.startswith(b"HPR1") and len(plaintext) >= 44:
            reg_aad = aad_base + b"\x00" + label.encode("utf-8") + b":r"
            reg_key = (
                _hkdf_layer(contact_key, b"hc-config-part-v12", reg_aad)
                if schema == 12 else contact_key
            )
            plaintext = _xchacha20poly1305_decrypt(
                reg_key,
                plaintext[4:28],
                reg_aad,
                plaintext[28:],
            )
        sections.append((label, plaintext, sidecar))
    return env, main_plaintext, sections
def decrypt_hc_v4(
    file_bytes: bytes, password: Optional[str] = None, hwid: Optional[str] = None
) -> Dict[str, Any]:
    env, main_plaintext, sections = _decrypt_parts_v4(
        file_bytes, password=password, hwid=hwid
    )
    try:
        main_config = json.loads(main_plaintext.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise HCDecryptError("V4 main section is not valid UTF-8 JSON") from exc
    clean_config: List[Dict[str, Any]] = []
    other_sections: List[Dict[str, Any]] = []
    for label, plaintext, sidecar in sections:
        if plaintext.startswith(b"HPC1"):
            parsed = parse_hpc1(plaintext, label=label)
            clean_profile: Dict[str, Any] = {
                "name": parsed.get("name", ""),
                "protocol": parsed.get("protocol", ""),
                "host": parsed.get("host", ""),
                "port": parsed.get("port", 0),
                "username": parsed.get("username", ""),
                "password": parsed.get("password", ""),
                "mode": parsed.get("mode", ""),
            }
            options = parsed.get("options", {})
            if isinstance(options, dict):
                for opt_key, opt_value in options.items():
                    clean_profile[opt_key] = opt_value
            if parsed.get("payload"):
                clean_profile["payload"] = parsed.get("payload")
            if sidecar is not None:
                try:
                    clean_profile["custom_payload_sidecar"] = sidecar.decode("utf-8")
                except UnicodeDecodeError:
                    clean_profile["custom_payload_sidecar_hex"] = sidecar.hex()
            clean_config.append(clean_profile)
            continue
        try:
            decoded: Any = plaintext.decode("utf-8")
            if decoded.startswith(("{", "[")):
                decoded = json.loads(decoded)
        except (UnicodeDecodeError, json.JSONDecodeError):
            decoded = {"hex": plaintext.hex()}
        other_sections.append({"label": label, "content": decoded})
    result: Dict[str, Any] = {
        "config": clean_config,
        "protections": _normalize_protection_keys(
            main_config.get("g", {}) if isinstance(main_config, dict) else {}
        ),
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
    if match:
        return match.group(0)
    return None
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
MSG_PASSWORD_REQUIRED = (
    "⚠️ **PASSWORD REQUIRED**\n\n"
)
MSG_HWID_REQUIRED = (
    "⚠️ **HWID REQUIRED**\n\n"
)
MSG_HWID_PASSWORD_REQUIRED = (
    "⚠️ **HWID + PASSWORD REQUIRED**\n\n"
)
MSG_AUTH_FAILED = (
    "⚠️ **WRONG PASSWORD / HWID**\n\n"
)
MSG_WRONG_TYPE = "INVALID_INPUT: expected nonempty HC file bytes"
MSG_V4_EXTRA_PROTECTION = "EXTRA_PROTECTION_REQUIRED: original authorized activation material is missing"
def _run_bytes(file_bytes: bytes, password: Optional[str], hwid: Optional[str]):
    fully_unpacked = None
    try:
        fully_unpacked = decrypt_hc_v79(file_bytes, password=password, hwid=hwid)
    except HCDecryptError as hc_err:
        message = str(hc_err)
        lower = message.lower()
        if "provide both" in lower:
            return MSG_HWID_PASSWORD_REQUIRED
        if "provide --hwid" in lower or "hwid-protected" in lower:
            return MSG_HWID_REQUIRED
        if "password-protected" in lower and password is None:
            return MSG_PASSWORD_REQUIRED
        if "does not match any authenticated" in lower:
            return MSG_AUTH_FAILED
        if "authentication failed" in lower and password:
            return MSG_AUTH_FAILED
    except Exception:
        pass
    if not fully_unpacked:
        try:
            fully_unpacked = decrypt_hc_v4(file_bytes, password=password, hwid=hwid)
        except HCDecryptError as hc_err:
            message = str(hc_err)
            lower = message.lower()
            if "access_id_private_key_required" in lower:
                return "ACCESS_ID_PRIVATE_KEY_REQUIRED: the public ID is not the recipient private key"
            if "unsupported_hwid_schedule_n16" in lower:
                return "UNSUPPORTED_HWID_SCHEDULE_N16: not implemented; no conclusion about the credentials"
            if "extra protection" in lower or "n13" in lower:
                return MSG_V4_EXTRA_PROTECTION
            if "provide both" in lower:
                return MSG_HWID_PASSWORD_REQUIRED
            if "provide --hwid" in lower or "hwid-protected" in lower:
                return MSG_HWID_REQUIRED
            if "password-protected" in lower and password is None:
                return MSG_PASSWORD_REQUIRED
            if "does not match any authenticated" in lower:
                return MSG_AUTH_FAILED
            if "authentication failed" in lower and password:
                return MSG_AUTH_FAILED
        except Exception:
            pass
    if not fully_unpacked:
        try:
            legacy_res = decrypt_legacy_hc(file_bytes)
            if legacy_res:
                fully_unpacked = legacy_res
        except Exception:
            pass
    if not fully_unpacked:
        return (
            "⚠️ **DECRYPTION FAILED:**\n"
            "The file is not a valid or supported HTTP Custom envelope."
        )
    return (
        f"HABIBIxNULLPTRO HTTP CUSTOM SCRIPT\n"
        f"{'='*30}\n\n"
        f"{json.dumps(fully_unpacked, indent=4, ensure_ascii=False)}\n\n"
        f"{'='*30}\n"
        f"code : @HABIBI_1ST and @NullptrO"
    )
def run(file_bytes, password: Optional[str] = None, hwid: Optional[str] = None):
    password, hwid = _parse_auth_inputs(password, hwid)
    data = file_bytes
    if isinstance(data, str):
        candidates = [data]
        try:
            candidates.append(data.encode("utf-8").decode("utf-8"))  # noqa
        except Exception:
            pass
        normalized = None
        for cand in candidates:
            try:
                normalized = cand.encode("latin-1")  # undo utf-8 carrier (mojibake)
                break
            except UnicodeEncodeError:
                continue
        if normalized is None:
            try:
                normalized = candidates[0].encode("utf-8")
            except Exception:
                return MSG_WRONG_TYPE
        data = normalized
    if not isinstance(data, bytes):
        return MSG_WRONG_TYPE
    if hwid is None and isinstance(password, str):
        try:
            env = _open_outer_envelope(data)
            if env.get("e") in ("n2", "n8") and not bool(env.get("h", 0)):
                _normalize_hwid(password)
                hwid, password = password, None
        except Exception:
            pass
    if not data:
        return MSG_WRONG_TYPE
    return _run_bytes(data, password, hwid)

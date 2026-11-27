import hashlib, hmac, json, struct, sys, re, base64, ctypes, ctypes.util
from typing import Any, Dict, List, Optional, Tuple

try:
    from Crypto.Cipher import ChaCha20_Poly1305
    CRYPTO_OK = True
except ImportError:
    CRYPTO_OK = False

PKG = b"xyz.easypro.httpcustom"
OUTER_AAD = b"HCX1|xyz.easypro.httpcustom|1"
OUTER_SEED = b"hc-envelope-seal-v1 xyz.easypro.httpcustom"
OUTER_SALT = b"hc-envelope-seal-salt-v1"
OUTER_INFO = b"hc-envelope-seal-info-v1"
OUTER_KEY_V3 = bytes.fromhex("88702df6ae8c089c9478b8cd2bd3f30961b3574a58063d024bdc50f6b779e26f")
N7_HMAC_KEY = bytes.fromhex("9ba7ff3baf33db7aad807a86574b7ca55bef2f048ead51f3a1fe0cff389db3b3")
C0_PREFIX = bytes.fromhex(
    "95dd433d7e4a0be02d55cc62553edcfc8f077fe780be5a7da7f861c2558dc181"
    "38cabb40b2f81a5a30b11a97cbcf0fed755aa8c2b5495e9bc0c1902077a4cd92"
)

class HCError(ValueError):
    pass
    
def _c0(data: bytes) -> bytes:
    return hashlib.sha256(C0_PREFIX + data).digest()

def _hkdf(ikm: bytes, salt: bytes, info: bytes, length: int = 32) -> bytes:
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    out, prev, ctr = b"", b"", 1
    while len(out) < length:
        prev = hmac.new(prk, prev + info + bytes([ctr]), hashlib.sha256).digest()
        out += prev; ctr += 1
    return out[:length]

def _rol(v: int, b: int) -> int:
    return ((v << b) & 0xFFFFFFFF) | (v >> (32 - b))

def _qr(s: List[int], a: int, b: int, c: int, d: int) -> None:
    s[a] = (s[a] + s[b]) & 0xFFFFFFFF; s[d] = _rol(s[d] ^ s[a], 16)
    s[c] = (s[c] + s[d]) & 0xFFFFFFFF; s[b] = _rol(s[b] ^ s[c], 12)
    s[a] = (s[a] + s[b]) & 0xFFFFFFFF; s[d] = _rol(s[d] ^ s[a], 8)
    s[c] = (s[c] + s[d]) & 0xFFFFFFFF; s[b] = _rol(s[b] ^ s[c], 7)

def _rounds(s: List[int]) -> None:
    for _ in range(10):
        _qr(s,0,4,8,12); _qr(s,1,5,9,13); _qr(s,2,6,10,14); _qr(s,3,7,11,15)
        _qr(s,0,5,10,15); _qr(s,1,6,11,12); _qr(s,2,7,8,13); _qr(s,3,4,9,14)

def _hchacha20(key: bytes, nonce16: bytes) -> bytes:
    s = list(struct.unpack("<4I", b"expand 32-byte k") + struct.unpack("<8I", key) + struct.unpack("<4I", nonce16))
    _rounds(s)
    return struct.pack("<8I", s[0],s[1],s[2],s[3],s[12],s[13],s[14],s[15])

def _chacha_block(key: bytes, nonce12: bytes, ctr: int) -> bytes:
    init = list(struct.unpack("<4I", b"expand 32-byte k") + struct.unpack("<8I", key) + (ctr & 0xFFFFFFFF,) + struct.unpack("<3I", nonce12))
    s = init.copy(); _rounds(s)
    return struct.pack("<16I", *((s[i] + init[i]) & 0xFFFFFFFF for i in range(16)))

def _stream_xor(data: bytes, key: bytes, nonce12: bytes, ctr: int = 1) -> bytes:
    out = bytearray(len(data))
    for bn, off in enumerate(range(0, len(data), 64)):
        st = _chacha_block(key, nonce12, ctr + bn)
        for i, v in enumerate(data[off:off+64]): out[off+i] = v ^ st[i]
    return bytes(out)

def _poly1305(msg: bytes, otk: bytes) -> bytes:
    r = int.from_bytes(otk[:16], "little") & 0x0FFFFFFC0FFFFFFC0FFFFFFC0FFFFFFF
    pad = int.from_bytes(otk[16:], "little"); acc = 0; mod = (1 << 130) - 5
    for off in range(0, len(msg), 16):
        acc = ((acc + int.from_bytes(msg[off:off+16] + b"\x01", "little")) * r) % mod
    return ((acc + pad) & ((1 << 128) - 1)).to_bytes(16, "little")

def _pad16(d: bytes) -> bytes:
    return b"" if len(d) % 16 == 0 else b"\x00" * (16 - len(d) % 16)

def _xdec_pure(key: bytes, nonce: bytes, aad: bytes, ct_tag: bytes) -> bytes:
    sub = _hchacha20(key, nonce[:16]); n12 = b"\x00\x00\x00\x00" + nonce[16:]
    ct, tag = ct_tag[:-16], ct_tag[-16:]
    otk = _chacha_block(sub, n12, 0)[:32]
    mac = aad + _pad16(aad) + ct + _pad16(ct) + struct.pack("<Q", len(aad)) + struct.pack("<Q", len(ct))
    if not hmac.compare_digest(_poly1305(mac, otk), tag):
        raise HCError("XChaCha20-Poly1305 auth failed")
    return _stream_xor(ct, sub, n12, 1)

def _xdec(key: bytes, nonce: bytes, aad: bytes, ct_tag: bytes) -> bytes:
    if len(key) != 32 or len(nonce) != 24 or len(ct_tag) < 16:
        raise HCError("bad XChaCha20 input")
    if CRYPTO_OK:
        c = ChaCha20_Poly1305.new(key=key, nonce=nonce); c.update(aad)
        try: return c.decrypt_and_verify(ct_tag[:-16], ct_tag[-16:])
        except ValueError: raise HCError("XChaCha20-Poly1305 auth failed")
    try:
        from nacl.bindings import crypto_aead_xchacha20poly1305_ietf_decrypt
        from nacl.exceptions import CryptoError
        try: return crypto_aead_xchacha20poly1305_ietf_decrypt(ct_tag, aad, nonce, key)
        except CryptoError: raise HCError("XChaCha20-Poly1305 auth failed")
    except ImportError:
        return _xdec_pure(key, nonce, aad, ct_tag)

def _argon2id(pw: bytes, salt: bytes, ops: int, mem: int, length: int = 32) -> bytes:
    if len(salt) != 16: raise HCError("Argon2 salt must be 16 bytes")
    try:
        from nacl.pwhash import argon2id
        return argon2id.kdf(length, pw, salt, opslimit=ops, memlimit=mem)
    except ImportError: pass
    try:
        from argon2.low_level import Type, hash_secret_raw
        return hash_secret_raw(pw, salt, time_cost=ops, memory_cost=mem // 1024, parallelism=1, hash_len=length, type=Type.ID, version=19)
    except ImportError: pass
    try:
        from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
        return Argon2id(salt=salt, length=length, iterations=ops, lanes=1, memory_cost=mem // 1024).derive(pw)
    except (ImportError, AttributeError): pass
    # libsodium via ctypes
    for soname in ["libsodium.so.23", "libsodium.so", "libargon2.so.1", "libargon2.so",
                   "/data/data/com.termux/files/usr/lib/libsodium.so",
                   "/data/data/com.termux/files/usr/lib/libargon2.so"]:
        try:
            lib = ctypes.CDLL(soname)
            if hasattr(lib, "crypto_pwhash"):
                out = (ctypes.c_ubyte * length)()
                if lib.crypto_pwhash(out, ctypes.c_ulonglong(length), pw, ctypes.c_ulonglong(len(pw)), salt,
                                     ctypes.c_ulonglong(ops), ctypes.c_size_t(mem), ctypes.c_int(2)) == 0:
                    return bytes(out)
            elif hasattr(lib, "argon2id_hash_raw"):
                out = (ctypes.c_ubyte * length)()
                if lib.argon2id_hash_raw(ctypes.c_uint32(ops), ctypes.c_uint32(mem // 1024), ctypes.c_uint32(1),
                                          pw, len(pw), salt, len(salt), out, length) == 0:
                    return bytes(out)
        except (OSError, AttributeError): continue
    raise RuntimeError("Need pynacl / argon2-cffi / cryptography / libsodium for password-protected files")

def _outer_key() -> bytes:
    return _hkdf(_c0(OUTER_SEED), OUTER_SALT, OUTER_INFO)

def _carriers(data: bytes):
    seen, cur = set(), data
    for _ in range(6):
        if cur in seen: break
        seen.add(cur)
        if len(cur) >= 40: yield cur
        try: text = cur.decode("utf-8")
        except UnicodeDecodeError: break
        if not all(ord(c) <= 0xFF for c in text): break
        nxt = bytes(ord(c) for c in text)
        if nxt == cur: break
        cur = nxt

def _open_outer(data: bytes) -> Dict[str, Any]:
    key = _outer_key(); last_err = None
    for logical in _carriers(data):
        if len(logical) < 40: continue
        # Standard outer
        try:
            pt = _xdec(key, logical[:24], OUTER_AAD, logical[24:])
            v = json.loads(pt.decode("utf-8"))
            if isinstance(v, dict): return v
        except (HCError, UnicodeDecodeError, json.JSONDecodeError) as e: last_err = e
        # V3 outer
        try:
            nonce, ct = logical[:24], logical[24:-16]
            sub = _hchacha20(OUTER_KEY_V3, nonce[:16]); n12 = b"\x00\x00\x00\x00" + nonce[16:]
            pt = _stream_xor(ct, sub, n12, 1)
            v = json.loads(pt.decode("utf-8"))
            if isinstance(v, dict) and v.get("a") == "HCCFG": return v
        except (HCError, UnicodeDecodeError, json.JSONDecodeError) as e: last_err = e
    raise HCError("Not a valid HTTP Custom envelope") from last_err

def _validate(env: Dict[str, Any]) -> int:
    if env.get("a") != "HCCFG": raise HCError(f"Bad magic: {env.get('a')!r}")
    schema = int(env.get("b", 0))
    if schema == 1: exp_c, exp_k = "XCHACHA20P1305", "NATIVE-HKDF-SHA256"
    elif schema in (2, 5, 7): exp_c, exp_k = "s1", "h1"
    else: raise HCError(f"Unsupported schema b={schema}")
    if env.get("c") != exp_c: raise HCError(f"Bad cipher: {env.get('c')!r}")
    if env.get("d") != exp_k: raise HCError(f"Bad KDF: {env.get('d')!r}")
    if env.get("e") not in ("n1", "n2", "n7", "n8"): raise HCError(f"Bad schedule: {env.get('e')!r}")
    return schema

def _features(env: Dict[str, Any]) -> bytes:
    f = env.get("f")
    if not isinstance(f, list) or not all(isinstance(x, str) for x in f): raise HCError("Bad features")
    return ",".join(f).encode()

def _n_bytes(env: Dict[str, Any]) -> Optional[bytes]:
    n = env.get("n")
    if n is None or isinstance(n, bool): return None
    ni = int(n)
    if str(ni) != str(n) or ni < 0: raise HCError("Bad n value")
    return str(ni).encode()

def _norm_hwid(hwid: str) -> bytes:
    v = hwid.strip()
    if len(v) != 32: raise HCError("HWID must be 32 chars")
    if any(c not in "0123456789abcdefABCDEFhH" for c in v): raise HCError("Bad HWID chars")
    return v.upper().encode()

def _env_key(env: Dict[str, Any]) -> bytes:
    try: k = bytes.fromhex(env["g"])
    except (KeyError, TypeError, ValueError): raise HCError("Bad inner key")
    if len(k) != 32: raise HCError("Inner key must be 32 bytes")
    return k

def _pw_kdf(env: Dict[str, Any], password: str, ekey: bytes) -> Tuple[bytes, bytes]:
    kdf = env.get("k")
    if kdf not in ("ARGON2ID13", "a1"): raise HCError(f"Bad pw KDF: {kdf!r}")
    try: ops, mem = int(env["l"]), int(env["m"])
    except (KeyError, TypeError, ValueError): raise HCError("Bad Argon2 params")
    pk = _argon2id(password.encode(), ekey[:16], ops, mem)
    return pk, b"|1|ARGON2ID13|" + str(ops).encode() + b"|" + str(mem).encode()

def _h_flag(env: Dict[str, Any]) -> bool:
    h = env.get("h", 0)
    if h not in (0, 1, False, True): raise HCError(f"Bad h flag: {h!r}")
    return bool(h)

def _transcript(env: Dict[str, Any], ekey: bytes, hwid_b: Optional[bytes] = None, n7_mode: bool = False) -> bytes:
    feats = _features(env); nb = _n_bytes(env); vb = b"1"
    t = b"HCCFG\x00" + PKG + b"\x00" + vb + b"\x00" + feats + b"\x00"
    if nb: t += nb + b"\x00"
    if hwid_b is not None: t += b"hwid\x00" + hwid_b + b"\x00"
    t += ekey
    if n7_mode:
        return hmac.new(N7_HMAC_KEY, b"\xd3" + C0_PREFIX[:32] + t, hashlib.sha256).digest()
    return _c0(t)

def _derive(env: Dict[str, Any], password: Optional[str], hwid: Optional[str]) -> Tuple[bytes, bytes]:
    sched = env.get("e"); schema = _validate(env); ekey = _env_key(env)
    feats = _features(env); nb = _n_bytes(env); vb = b"1"
    is_hwid = sched in ("n2", "n8")
    is_n7 = sched in ("n7", "n8")

    if is_hwid and hwid is None:
        cnt = len(env.get("o", [])) if isinstance(env.get("o"), list) else 0
        raise HCError(f"HWID_REQUIRED:{cnt}")

    hwid_b = _norm_hwid(hwid) if is_hwid else None
    ikm = _transcript(env, ekey, hwid_b, n7_mode=is_n7)
    protected = _h_flag(env)
    aad_prot = b"|0"

    if protected:
        if password is None:
            raise HCError("HWID_PASSWORD_REQUIRED" if is_hwid else "PASSWORD_REQUIRED")
        pk, aad_prot = _pw_kdf(env, password, ekey)
        ikm = ikm + pk

    sched_b = sched.encode()
    info = b"app-config|" + sched_b + b"|" + PKG + b"|" + vb + b"|" + feats
    if nb: info += b"|" + nb
    if hwid_b: info += b"|hwid|" + hwid_b
    skey = _hkdf(ikm, ekey, info)

    aad = (b"HCCFG|" + str(schema).encode() + b"|XCHACHA20P1305|NATIVE-HKDF-SHA256|"
           + sched_b + b"|" + PKG + b"|" + vb + b"|" + feats + aad_prot)
    if nb: aad += b"|" + nb

    # For HWID schedules, try key slots
    if is_hwid:
        slots = env.get("o", [])
        if not isinstance(slots, list) or not slots: raise HCError("No HWID key slots")
        for slot in slots:
            if not isinstance(slot, dict): continue
            try:
                nonce = bytes.fromhex(slot["a"]); ct = bytes.fromhex(slot["b"])
                sk = _xdec(skey, nonce, aad + b"\x00w", ct)
                if len(sk) == 32: return sk, aad
            except (HCError, TypeError, ValueError, KeyError): continue
        raise HCError("AUTH_FAILED")

    return skey, aad
    
class _R:
    def __init__(self, d: bytes): self.d, self.o = d, 0
    def take(self, n: int) -> bytes:
        if self.o + n > len(self.d): raise HCError("Truncated HPC1")
        v = self.d[self.o:self.o+n]; self.o += n; return v
    def u32(self) -> int: return struct.unpack(">I", self.take(4))[0]
    def u64(self) -> int: return struct.unpack(">Q", self.take(8))[0]
    def txt(self) -> str:
        s = self.u32()
        if s > 16*1024*1024: raise HCError("HPC1 string too long")
        return self.take(s).decode("utf-8")

def _parse_hpc1(data: bytes, label: Optional[str]) -> Dict[str, Any]:
    r = _R(data)
    if r.take(4) != b"HPC1": raise HCError("Not HPC1")
    if r.u32() != 11: raise HCError("Bad HPC1 field count")
    name, proto, host = r.txt(), r.txt(), r.txt()
    port = r.u32(); user, pw, payload = r.txt(), r.txt(), r.txt()
    opts_txt = r.txt(); flags = r.u32(); updated = r.u64(); mode = r.txt()
    if r.o != len(data): raise HCError("HPC1 trailing bytes")
    try: opts = json.loads(opts_txt) if opts_txt else {}
    except json.JSONDecodeError: opts = opts_txt
    res: Dict[str, Any] = {"name": name, "protocol": proto, "host": host, "port": port,
                           "username": user, "password": pw, "payload": payload,
                           "options": opts, "flags": flags, "updated_at_ms": updated, "mode": mode}
    if label: res["label"] = label
    return res

def _dec_section(sec: Dict[str, Any], key: bytes, aad_base: bytes) -> bytes:
    try:
        label = sec["a"]; nonce = bytes.fromhex(sec["b"]); ct = bytes.fromhex(sec["c"])
    except (KeyError, TypeError, ValueError): raise HCError("Bad section")
    if not isinstance(label, str) or not label: raise HCError("Bad section label")
    return _xdec(key, nonce, aad_base + b"\x00" + label.encode(), ct)

def _dec_sidecar(sec: Dict[str, Any], key: bytes, aad_base: bytes) -> Optional[bytes]:
    nested = sec.get("d")
    if nested is None: return None
    if not isinstance(nested, dict): raise HCError("Bad sidecar")
    label = sec.get("a", "")
    try: nonce = bytes.fromhex(nested["a"]); ct = bytes.fromhex(nested["b"])
    except (KeyError, TypeError, ValueError): raise HCError("Bad sidecar data")
    return _xdec(key, nonce, aad_base + b"\x00" + label.encode() + b":x", ct)

def _dec_hpr1(data: bytes, key: bytes, aad_base: bytes, label: Optional[str]) -> bytes:
    if not data.startswith(b"HPR1") or len(data) < 44: return data
    nonce, ct_tag = data[4:28], data[28:]
    tag = (label or "s0").encode()
    try: return _xdec(key, nonce, aad_base + b"\x00" + tag + b":r", ct_tag)
    except HCError:
        sub = _hchacha20(key, nonce[:16]); n12 = b"\x00\x00\x00\x00" + nonce[16:]
        return _stream_xor(ct_tag[:-16], sub, n12, 1)

def _sec_list(v: Any) -> List[Dict[str, Any]]:
    if isinstance(v, list) and all(isinstance(x, dict) for x in v): return v
    if isinstance(v, dict) and all(isinstance(x, dict) for x in v.values()): return list(v.values())
    raise HCError("Bad section collection")

PKM = {"a":"accessMode","c":"expiryEnabled","d":"expiryTime","e":"noteEnabled",
       "f":"hwidLockEnabled","g":"hwids","h":"loginHwidEnabled",
       "j":"loginHwidAuthorizationRequired","l":"mobileDataOnly","m":"blockRoot",
       "o":"providerLockEnabled","p":"providerCodes","v":"note"}

HC_VERSIONS = {756:"7.9.21", 759:"7.9.24", 766:"7.9.28", 789:"7.10.7", 810:"7.10.12",
               831:"7.10.19", 848:"7.10.25", 859:"7.11.1", 864:"7.11.8"}

def _ver(n):
    try: return f"{HC_VERSIONS[int(n)]} ({int(n)})"
    except (KeyError, TypeError, ValueError): return f"build-{n}"

def _norm_prot(p: Any) -> Any:
    if not isinstance(p, dict): return p
    return {PKM.get(k, k): v for k, v in p.items()}

def decrypt(data: bytes, password: Optional[str] = None, hwid: Optional[str] = None) -> Dict[str, Any]:
    env = _open_outer(data)
    skey, aad_base = _derive(env, password, hwid)

    main_sec = env.get("i")
    if not isinstance(main_sec, dict): raise HCError("Missing main section")
    main_pt = _dec_section(main_sec, skey, aad_base)
    try: main_cfg = json.loads(main_pt.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError): raise HCError("Main section not JSON")

    profiles, others = [], []
    for sec in _sec_list(env.get("j", [])):
        pt = _dec_section(sec, skey, aad_base)
        label = sec.get("a")
        if pt.startswith(b"HPR1"): pt = _dec_hpr1(pt, skey, aad_base, label)
        sidecar = _dec_sidecar(sec, skey, aad_base)
        if pt.startswith(b"HPC1"):
            prof = _parse_hpc1(pt, label)
            if sidecar:
                try: prof["custom_payload_sidecar"] = sidecar.decode("utf-8")
                except UnicodeDecodeError: prof["custom_payload_sidecar_hex"] = sidecar.hex()
            profiles.append(prof)
        else:
            try:
                dec = pt.decode("utf-8")
                if dec.startswith(("{", "[")): dec = json.loads(dec)
            except (UnicodeDecodeError, json.JSONDecodeError): dec = {"hex": pt.hex()}
            others.append({"label": label, "content": dec})

    # Clean output
    clean = []
    for p in profiles:
        cp: Dict[str, Any] = {"name": p.get("name",""), "protocol": p.get("protocol",""),
                              "host": p.get("host",""), "port": p.get("port",0),
                              "username": p.get("username",""), "password": p.get("password",""),
                              "mode": p.get("mode","")}
        opts = p.get("options", {})
        if isinstance(opts, dict):
            for k, v in opts.items(): cp[k] = v
        if p.get("payload"): cp["payload"] = p["payload"]
        if "custom_payload_sidecar" in p: cp["custom_payload_sidecar"] = p["custom_payload_sidecar"]
        if "custom_payload_sidecar_hex" in p: cp["custom_payload_sidecar_hex"] = p["custom_payload_sidecar_hex"]
        clean.append(cp)

    result: Dict[str, Any] = {"app_version": _ver(env.get("n")),
                              "config": clean, "protections": _norm_prot(main_cfg.get("g", {}) if isinstance(main_cfg, dict) else {})}
    if others: result["other_sections"] = others
    return result

def _parse_auth(text: Optional[str]) -> Tuple[Optional[str], Optional[str]]:
    if not text or not text.strip(): return None, None
    t = text.strip()
    pw = re.search(r"(?im)^\s*(?:only\s+)?pass(?:word)?\s*(?:[:\-–—=]\s*|\s+)(.+?)\s*$", t)
    hw = re.search(r"(?im)^\s*hwid\s*(?:[:\-–—=]\s*|\s+)(.+?)\s*$", t)
    password = pw.group(1).strip() if pw else None
    hwid = None
    if hw:
        cleaned = re.sub(r"[^0-9A-Za-z]", "", hw.group(1))
        m = re.search(r"[0-9a-fAhH]{32}", cleaned)
        hwid = m.group(0) if m else None
    if hwid is None and not pw:
        cleaned = re.sub(r"[^0-9A-Za-z]", "", t)
        if re.fullmatch(r"[0-9a-fAhH]{32}", cleaned): hwid = cleaned
    return password, hwid

def main():
    if len(sys.argv) < 2:
        print("Usage: python hc.py <file.hc>"); sys.exit(1)

    path = sys.argv[1]
    try:
        with open(path, "rb") as f: data = f.read()
    except FileNotFoundError:
        print(f"Error: File not found: {path}"); sys.exit(1)
    except Exception as e:
        print(f"Error reading file: {e}"); sys.exit(1)

    if not data:
        print("Error: Empty file"); sys.exit(1)

    auth_text = " ".join(sys.argv[2:]) if len(sys.argv) > 2 else None
    password, hwid = _parse_auth(auth_text)

    for attempt in range(4):
        try:
            result = decrypt(data, password=password, hwid=hwid)
            out = json.dumps(result, indent=4, ensure_ascii=False)
            print(" HTTP CUSTOM SCRIPT\n" + "=" * 30 + "\n\n" +
                  out + "\n\n" + "=" * 30 + "\ncode : @Gh0stDeveloper")
            return
        except HCError as e:
            msg = str(e)
            if msg == "PASSWORD_REQUIRED":
                password = input("Password: ").strip() or None
                if password is None: print("Password required!"); sys.exit(1)
            elif msg.startswith("HWID_REQUIRED"):
                hwid = input("HWID (32 chars): ").strip() or None
                if hwid is None: print("HWID required!"); sys.exit(1)
            elif msg == "HWID_PASSWORD_REQUIRED":
                password = input("Password: ").strip() or None
                hwid = input("HWID (32 chars): ").strip() or None
                if password is None or hwid is None: print("Both required!"); sys.exit(1)
            elif msg == "AUTH_FAILED":
                print("Wrong password/HWID! Try again.")
                password = input("Password: ").strip() or None
                hwid = input("HWID (32 chars): ").strip() or None
            else:
                print(f"Error: {msg}"); sys.exit(1)
        except Exception as e:
            print(f"Error: {e}"); sys.exit(1)

    print("Error: Too many failed attempts"); sys.exit(1)

if __name__ == "__main__":
    main()
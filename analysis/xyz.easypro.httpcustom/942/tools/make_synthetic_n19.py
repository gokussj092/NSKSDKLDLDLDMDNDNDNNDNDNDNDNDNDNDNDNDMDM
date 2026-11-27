"""Synthetic HC b=14/n19 + b=12/n15 fixture builder (independent encryptor).
Uses only the public crypto definitions from the cloud reference (staging
codec_n19.py / crypto_n19.py + _hc_hccfg.py fetched from ci) and pycryptodome.
No real user files. Deterministic nonces/seed."""
import json, os, struct, subprocess, sys, tempfile
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), 'ref_oracle'))
import codec, crypto
from crypto import native_fold_n15, native_fold_n19
import _hc_hccfg as hist
from Crypto.Cipher import ChaCha20_Poly1305

PKG = b"xyz.easypro.httpcustom"
SEED = bytes(range(32))

def seal(key, nonce, aad, pt):
    c = ChaCha20_Poly1305.new(key=key, nonce=nonce)
    c.update(aad)
    ct, tag = c.encrypt_and_digest(pt)
    return ct + tag

def txt(s):
    b = s.encode()
    return struct.pack(">I", len(b)) + b

def hpc1(name="synth", host="example.org", payload="GET / HTTP/1.1"):
    out = b"HPC1" + struct.pack(">I", 11)
    out += txt(name) + txt("ssh") + txt(host) + struct.pack(">I", 443)
    out += txt("user") + txt("pass") + txt(payload)
    out += txt('{"opt": true}') + struct.pack(">I", 3) + struct.pack(">Q", 123456789) + txt("modeX")
    return out

def build(schedule, protected=False, password=None, banner="dict", extra_prot=None, hpr1=False, sidecar=True):
    assert schedule in ("n19", "n15")
    b = 14 if schedule == "n19" else 12
    build_no = 942 if schedule == "n19" else 934
    feats = b"ssh,profiles"
    env = {"a": "HCCFG", "b": b, "c": "s1", "d": "h1", "e": schedule,
           "f": ["ssh", "profiles"], "g": SEED.hex(), "h": 1 if protected else 0, "n": build_no}
    prot_aad = b"|0"
    pwkey = b""
    if protected:
        env.update({"k": "a1", "l": 2, "m": 8*1024*1024})
        pwkey, prot_aad = hist._pw_kdf(env, password, SEED)
    aad = (b"HCCFG|" + str(b).encode() + b"|XCHACHA20P1305|NATIVE-HKDF-SHA256|"
           + schedule.encode() + b"|" + PKG + b"|1|" + feats + prot_aad + b"|" + str(build_no).encode())
    fold = native_fold_n19(aad) if schedule == "n19" else native_fold_n15(aad)
    label = b"hc-config-content-v14" if schedule == "n19" else b"hc-config-content-v12"
    key = hist._hkdf(fold + pwkey, SEED, label)
    def skey(lab, extra=b""):
        return hist._hkdf(key, b"hc-config-part-v12", aad + b"\x00" + lab.encode() + extra)
    # main section "g": full V4 map for n19, historical 13-key map for n15
    g = {"a": "free", "c": True, "d": 1893456000, "e": False, "f": True, "g": ["HWID1"],
         "h": False, "j": True, "l": False, "m": True, "o": False, "p": ["MX"], "v": "note-text"}
    if schedule == "n19":
        g.update({"b": True, "i": "schemeX", "k": False, "n": True, "q": "Telcel",
                  "r": True, "s": ["MX", "US"], "t": True, "u": ["com.blocked"],
                  "w": False,
                  "x": {"v": 1, "s": "custom", "h": "banner-text"} if banner == "dict" else "plain-banner",
                  "z": "unknown-kept"})
        if extra_prot: g.update(extra_prot)
    main = json.dumps({"g": g}, separators=(",", ":")).encode()
    env["i"] = {"a": "m", "b": bytes(range(24)).hex(),
                "c": seal(skey("m"), bytes(range(24)), aad + b"\x00m", main).hex()}
    prof = hpc1()
    if hpr1:
        inner_nonce = bytes(range(40, 64))
        prof = b"HPR1" + inner_nonce + seal(skey("s0", b":r"), inner_nonce, aad + b"\x00s0:r", prof)
    sec = {"a": "s0", "b": bytes(range(24, 48)).hex(),
           "c": seal(skey("s0"), bytes(range(24, 48)), aad + b"\x00s0", prof).hex()}
    if sidecar:
        sec["d"] = {"a": bytes(range(48, 72)).hex(),
                    "b": seal(skey("s0", b":x"), bytes(range(48, 72)), aad + b"\x00s0:x", b"custom-payload").hex()}
    other = json.dumps({"other": [1, 2]}).encode()
    env["j"] = [sec, {"a": "c0", "b": bytes(range(72, 96)).hex(),
                      "c": seal(skey("c0"), bytes(range(72, 96)), aad + b"\x00c0", other).hex()}]
    outer_nonce = bytes(range(96, 120))
    return outer_nonce + seal(codec.OUTER_KEY, outer_nonce, codec.OUTER_AAD,
                              json.dumps(env, separators=(",", ":")).encode())

HARNESS = sys.argv[1] if len(sys.argv) > 1 else os.environ.get("HC_HARNESS", "./hc_harness_n19")
HARNESS_ORIG = sys.argv[2] if len(sys.argv) > 2 else os.environ.get("HC_HARNESS_ORIG", "./hc_harness_orig")

def run_harness(exe, data, pw="", hwid=""):
    with tempfile.NamedTemporaryFile(delete=False, suffix=".hc") as f:
        f.write(data); path = f.name
    try:
        return subprocess.run([exe, path, pw, hwid], capture_output=True)
    finally:
        os.unlink(path)

def check(name, cond, extra=""):
    print(("PASS " if cond else "FAIL ") + name + ((" | " + extra) if extra else ""))
    return cond

def main():
    ok = True
    # --- 1. n19 unprotected: C++ == Python ref (full JSON), banner dict ---
    data = build("n19")
    ref = codec.decrypt(data)
    r = run_harness(HARNESS, data)
    got = json.loads(r.stdout) if r.returncode == 0 else None
    ok &= check("n19 plain: C++ == Python ref", r.returncode == 0 and got == ref,
                f"rc={r.returncode} banner={got['protections'].get('tunnelBanner') if got else r.stderr.decode()[:80]}")
    ok &= check("n19 plain: V4 keys present", got is not None and got["protections"].get("remoteProxyUnlocked") is True
                and got["protections"].get("expiryRequiresAutomaticTime") is False
                and got["protections"].get("countryCodes") == ["MX", "US"]
                and got["protections"].get("z") == "unknown-kept")
    ok &= check("n19 plain: sidecar + profile", got is not None and got["config"][0].get("custom_payload_sidecar") == "custom-payload"
                and got["config"][0]["payload"] == "GET / HTTP/1.1" and len(got["other_sections"]) == 1)

    # --- 2. n19 protected (cloud composition): correct pw opens, wrong/missing fail ---
    PW = "s3cret-pw"
    data_p = build("n19", protected=True, password=PW)
    ref_p = codec.decrypt(data_p, password=PW)
    r = run_harness(HARNESS, data_p, PW)
    got_p = json.loads(r.stdout) if r.returncode == 0 else None
    ok &= check("n19 protected: C++ == Python ref (correct pw)", r.returncode == 0 and got_p == ref_p,
                f"rc={r.returncode} {r.stderr.decode()[:80]}")
    r = run_harness(HARNESS, data_p, "wrong")
    ok &= check("n19 protected: wrong pw -> AUTH_FAILED", r.returncode != 0 and b"AUTH_FAILED" in r.stderr, r.stderr.decode().strip()[:80])
    r = run_harness(HARNESS, data_p)
    ok &= check("n19 protected: missing pw -> PASSWORD_REQUIRED", r.returncode != 0 and b"PASSWORD_REQUIRED" in r.stderr, r.stderr.decode().strip()[:80])

    # --- 3. n19 HPR1-wrapped profile + banner as plain string ---
    data_h = build("n19", hpr1=True, banner="str")
    ref_h = codec.decrypt(data_h)
    r = run_harness(HARNESS, data_h)
    got_h = json.loads(r.stdout) if r.returncode == 0 else None
    ok &= check("n19 HPR1 + string banner: C++ == Python ref", r.returncode == 0 and got_h == ref_h,
                f"rc={r.returncode} banner={got_h['protections'].get('tunnelBanner') if got_h else r.stderr.decode()[:80]}")

    # --- 4. n19 tamper: flip one byte in profile ciphertext -> must fail ---
    bad = bytearray(data); bad[-30] ^= 0x01
    r = run_harness(HARNESS, bytes(bad))
    ok &= check("n19 tampered -> rejected", r.returncode != 0, r.stderr.decode().strip()[:80])

    # --- 5. n15 regression: new binary stdout == orig binary stdout == Python ref ---
    data15 = build("n15")
    ref15 = codec.decrypt(data15)
    rn = run_harness(HARNESS, data15)
    ro = run_harness(HARNESS_ORIG, data15)
    ok &= check("n15 synthetic: new == orig (byte-identical stdout)", rn.returncode == 0 and ro.returncode == 0 and rn.stdout == ro.stdout)
    ok &= check("n15 synthetic: == Python ref", rn.returncode == 0 and json.loads(rn.stdout) == ref15)
    ok &= check("n15 synthetic: historical 13-key map kept (x stays 'x', no V4 keys)",
                rn.returncode == 0 and json.loads(rn.stdout)["protections"].get("x") is None
                and "remoteProxyUnlocked" not in json.loads(rn.stdout)["protections"])
    data15p = build("n15", protected=True, password=PW)
    rn = run_harness(HARNESS, data15p, PW)
    ro = run_harness(HARNESS_ORIG, data15p, PW)
    ok &= check("n15 protected synthetic: new == orig", rn.returncode == 0 and rn.stdout == ro.stdout)

    print("ALL OK" if ok else "SOME FAILED")
    return 0 if ok else 1

if __name__ == "__main__":
    sys.exit(main())

"""Tweak-field decryptor for ASL Tunnel catalog (LyT0.b via Lln.I):
AES/CBC/PKCS7Padding, key = ASCII hex (32 chars) of MD5(UTF-8(" "*29 + "." + " "*33)),
IV = 3c7f1a9d55e3c0b28e216d4a97ff1362. Input is Base64 (padding may be missing).
"""
import base64, hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

KEY_STR = " " * 29 + "." + " " * 33
KEY = hashlib.md5(KEY_STR.encode("utf-8")).hexdigest().encode("ascii")  # 32 bytes -> AES-256
IV = bytes.fromhex("3c7f1a9d55e3c0b28e216d4a97ff1362")

def tweak_decrypt(s: str) -> str:
    if s is None or s == "":
        return ""
    b64 = s.strip()
    b64 += "=" * (-len(b64) % 4)
    ct = base64.b64decode(b64)
    pt = AES.new(KEY, AES.MODE_CBC, iv=IV).decrypt(ct)
    return unpad(pt, 16).decode("utf-8")

if __name__ == "__main__":
    import json
    d = json.load(open("live_alt_decrypted.json"))
    t = d["Tweaks"][0]
    for k, v in t.items():
        if isinstance(v, str) and v:
            try:
                print(f"Tweak0.{k}: {tweak_decrypt(v)!r}")
            except Exception as e:
                print(f"Tweak0.{k}: ERR {type(e).__name__} {e} (raw {v[:50]!r})")
    print("--- server Info/Message full ---")
    import fieldcrypt
    print("Server0.Info:", repr(fieldcrypt.field_decrypt(d["Servers"][0]["Info"])[:300]))
    print("Message:", repr(fieldcrypt.field_decrypt(d["Message"])[:300]))

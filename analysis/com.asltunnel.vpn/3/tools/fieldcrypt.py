"""Field decryptor for ASL Tunnel catalog (LpR0.a via Lln.H):
AES/CFB/NoPadding, key = SHA-256(UTF-8(" "*61 + "'" + " "*12 + "." + " "*8)),
IV = 4e6a2c8153d9b4a7903f685ca1ef2479. Input is Base64 (padding may be missing).
"""
import base64, hashlib
from Crypto.Cipher import AES

KEY_STR = " " * 61 + "'" + " " * 12 + "." + " " * 8
KEY = hashlib.sha256(KEY_STR.encode("utf-8")).digest()
IV = bytes.fromhex("4e6a2c8153d9b4a7903f685ca1ef2479")

def field_decrypt(s: str) -> str:
    if s is None or s == "":
        return ""
    b64 = s.strip()
    b64 += "=" * (-len(b64) % 4)
    ct = base64.b64decode(b64)
    pt = AES.new(KEY, AES.MODE_CFB, iv=IV, segment_size=128).decrypt(ct)
    return pt.decode("utf-8")

if __name__ == "__main__":
    import json
    d = json.load(open("live_alt_decrypted.json"))
    tests = [
        ("Version", d["Version"]),
        ("Message(short)", d["Message"][:40]),
        ("Banner_ID", d["Banner_ID"]),
        ("cardMessage", d["cardMessage"]),
        ("cardLink", d["cardLink"]),
        ("Server0.Name", d["Servers"][0]["Name"]),
        ("Server0.Flag", d["Servers"][0]["Flag"]),
        ("Server0.Info", d["Servers"][0]["Info"][:60]),
        ("Server0.TCPPort", d["Servers"][0]["TCPPort"]),
        ("Server0.SSLPort", d["Servers"][0]["SSLPort"]),
        ("Tweak0.Name", d["Tweaks"][0]["Name"]),
        ("Tweak0.Payload", d["Tweaks"][0]["Payload"]),
        ("Tweak0.Sni", d["Tweaks"][0]["Sni"]),
        ("Tweak0.ProxyHost", d["Tweaks"][0]["ProxyHost"]),
        ("Tweak0.ProxyPort", d["Tweaks"][0]["ProxyPort"]),
        ("Tweak0.Flag", d["Tweaks"][0]["Flag"]),
    ]
    for name, val in tests:
        try:
            print(f"{name}: {field_decrypt(val)!r}")
        except Exception as e:
            print(f"{name}: ERR {e} (raw {val[:50]!r})")

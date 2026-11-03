"""Independent build59 reference: libsodium Argon2id and Java/JCA GCM.

Does not import production decoders. Only synthetic data is printed by generate.
"""
from __future__ import annotations

import base64
import json
import re

from tests.golden.enaa_reference import aes_batch, kdf

EXPORT_PASSWORD = b"/4ssU0OjjtKH8AheiAxnc3DwSGDzsy+8"
FIELD_PASSWORD = b"NurChickenPowder"
TOP = ("DefOVPNUser", "DefOVPNPass", "HysteriaUser", "HysteriaOBFS", "DefaultOVPNCert")
SERVER = ("ServerIPHost", "OVPNUser", "OVPNPass", "UDP_obfs", "UDP_user", "CustomCertificate",
          "SlowDNSHost", "SlowDNSKey", "V2rayUUID", "V2rayPath", "H2pass", "TrojanPass")
NETWORK = ("Payload", "CustomProxy", "SNI", "V2rayConfig", "BugDNS", "V2rayAddress", "V2rayHost", "V2raySNI")


def seal(text, exported=False, counter=0):
    salt = bytes((i + counter) % 256 for i in range(16))
    nonce = bytes((i + counter + 89) % 256 for i in range(12))
    key = kdf(EXPORT_PASSWORD if exported else FIELD_PASSWORD, salt)
    line = "\t".join(["E", key.hex(), salt.hex(), nonce.hex(), base64.b64encode(text.encode()).decode()])
    encoded = base64.b64encode(salt + nonce + aes_batch([line])[0]).decode()
    return encoded[:3] + "Q" + encoded[3:] if exported else encoded


def open_many(values):
    lines = []
    for text, exported in values:
        if exported:
            text = text[:3] + text[4:]
        raw = base64.b64decode(text.replace("\r", "").replace("\n", ""), validate=True)
        key = kdf(EXPORT_PASSWORD if exported else FIELD_PASSWORD, raw[:16])
        lines.append("\t".join(["D", key.hex(), raw[:16].hex(), raw[16:28].hex(), base64.b64encode(raw[28:]).decode()]))
    return [data.decode("utf-8") for data in aes_batch(lines)] if lines else []


def catalog_reference(data):
    text = data.decode("utf-8-sig").strip()
    if not text.startswith("{"):
        text = open_many([(text, len(text.replace("\r", "").replace("\n", "")) % 4 == 1)])[0]
    doc = json.loads(text)
    items = []
    def collect(row, keys):
        for key in keys:
            value = row.get(key)
            if isinstance(value, str):
                packed = value.replace("\r", "").replace("\n", "")
                if len(packed) >= 60 and re.fullmatch(r"[A-Za-z0-9+/]*={0,2}", packed):
                    items.append((row, key, value))
    collect(doc, TOP)
    for rows, keys in ((doc["Servers"], SERVER), (doc["Networks"], NETWORK)):
        for row in rows:
            collect(row, keys)
    unique = list(dict.fromkeys(value for _, _, value in items))
    opened = dict(zip(unique, open_many([(value, False) for value in unique])))
    for row, key, value in items:
        row[key] = opened[value]
    return doc, {"protectedFields": len(items), "uniqueFields": len(unique)}


def generate():
    payload = "GET /日本 HTTP/1.1\r\nHost: example.invalid\r\n\r\n"
    field = seal(payload, counter=7)
    address = seal("vpn.example.invalid", counter=9)
    empty = seal("", counter=11)
    server = {"Name": "Prueba 日本", **{key: address for key in SERVER}, "port": 443, "Enabled": False}
    network = {"Name": "Unicode ñ", **{key: field for key in NETWORK},
               "Info": field, "URI": True, "future": {"values": [False, None, "keep"]}}
    doc = {"Version": "test.59", **{key: empty for key in TOP}, "Servers": [server, dict(server)],
           "Networks": [network, dict(network)], "unknown": field}
    expected = {**doc, **{key: "" for key in TOP},
                "Servers": [{**server, **{key: "vpn.example.invalid" for key in SERVER}} for _ in range(2)],
                "Networks": [{**network, **{key: payload for key in NETWORK}} for _ in range(2)]}
    plain = json.dumps(doc, ensure_ascii=False, separators=(",", ":"))
    docs = [{"mode": mode, "wire": plain if mode == "plain" else seal(plain, mode == "remote", counter=20+i),
             "expected": expected} for i, mode in enumerate(("plain", "bundled", "remote"))]
    return {"documents": docs, "kdf": {"password": "synthetic test key", "saltHex": bytes(range(16)).hex(),
            "keyHex": kdf(b"synthetic test key", bytes(range(16))).hex()}}


if __name__ == "__main__":
    print(json.dumps(generate(), ensure_ascii=False, indent=2))

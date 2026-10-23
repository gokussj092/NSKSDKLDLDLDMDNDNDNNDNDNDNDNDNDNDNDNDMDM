"""1FTunnel 0.6.99: authenticated 1FT1 envelopes and complete CFG1 documents.

Offline reader reconstructed from liboneftunnel-security.so and u2.f. No network,
Android environment emulation, password search, or execution of profile values.
"""
from __future__ import annotations

import base64
import binascii
import hmac
import re
import struct

from Crypto.Cipher import AES

PREFIXES = ("1FTnl.", "1FT1.", "1ftunnel://1FTnl/", "1ftunnel://1FT1/")
ROOT_KEY = bytes.fromhex("9e4f569a0a6cfd2da000b9de35ffe74a4e605c3eaecbdf477a13d709da233971")
PACKAGE = "com.oneftunnel.app"
SIGNATURES = frozenset({
    "d5d6665868244981a7ce3e9ea543610af83ed3b9c00322f0a7ffed88d327d589",
    "0c7718166c0b60cb09229dfc5f8c02f2567ea41fb75f7c7b792111c65dfaf937",
})
TYPES = ("SSH", "VMESS", "VLESS", "TROJAN")


class DecodeError(ValueError):
    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


def require(condition: bool, code: str = "INVALID_FORMAT") -> None:
    if not condition:
        raise DecodeError(code)


class Reader:
    def __init__(self, data: bytes):
        self.data = data
        self.pos = 0

    def take(self, size: int) -> bytes:
        require(0 <= size <= len(self.data) - self.pos)
        out = self.data[self.pos:self.pos + size]
        self.pos += size
        return out

    def number(self, fmt: str) -> int:
        return struct.unpack(">" + fmt, self.take(struct.calcsize(fmt)))[0]

    def boolean(self) -> bool:
        n = self.number("B")
        require(n in (0, 1))
        return bool(n)

    def choice(self, names: tuple[str, ...]) -> str:
        n = self.number("B")
        require(n < len(names))
        return names[n]

    def string(self, *, nullable: bool = False, short: bool = False) -> str | None:
        size = self.number("H" if short else "i")
        if nullable and size == -1:
            return None
        require(0 <= size <= 2 * 1024 * 1024)
        try:
            return self.take(size).decode("utf-8")
        except UnicodeError as error:
            raise DecodeError("INVALID_FORMAT") from error

    def end(self) -> None:
        require(self.pos == len(self.data))


def unwrap(data: bytes | str) -> bytes:
    if isinstance(data, bytes) and data.startswith(b"1FT1") and not data.startswith(b"1FT1."):
        require(len(data) <= 5 * 1024 * 1024)
        return data
    try:
        text = data.decode("utf-8") if isinstance(data, bytes) else data
        require(isinstance(text, str))
        text = text.strip()
        prefix = next((p for p in PREFIXES if text.startswith(p)), None)
        require(prefix is not None)
        encoded = text[len(prefix):]
        require(0 < len(encoded) <= 393216)
        require(re.fullmatch(r"[A-Za-z0-9_-]+={0,2}", encoded) is not None)
        if "=" in encoded:
            require(len(encoded) % 4 == 0)
        raw = base64.b64decode(encoded + "=" * (-len(encoded) % 4), altchars=b"-_", validate=True)
        # Reject ignored padding bits and noncanonical lengths.
        require(base64.urlsafe_b64encode(raw).rstrip(b"=").decode() == encoded.rstrip("="))
        return b"1FT1" + raw
    except (UnicodeError, binascii.Error) as error:
        raise DecodeError("INVALID_FORMAT") from error


def parse_aad(data: bytes, outer_version: int) -> dict:
    r = Reader(data)
    version = r.number("B")
    require(version == outer_version and version in (1, 2, 3))
    out = {"version": version, "package": r.string(short=True),
           "signatureSha256": r.string(short=True), "configVersion": r.number("I")}
    require(out["configVersion"] > 0)
    out.update(keySlot=0, minimumAppBuild=None, createdAt=None)
    if version >= 2:
        out.update(keySlot=r.number("I"), minimumAppBuild=r.number("q"), createdAt=r.number("q"))
        require(out["keySlot"] in (0, 1) and out["minimumAppBuild"] >= 0 and out["createdAt"] >= 0)
    out["expiredAt"] = r.number("q")
    require(out["expiredAt"] >= -1)
    out["configType"] = r.choice(TYPES)
    out["lockMode"] = r.number("B")
    require(out["lockMode"] in (0, 1, 2))
    out["blockRoot"] = r.boolean() if version >= 3 else False
    r.end()
    require(out["package"] == PACKAGE and out["signatureSha256"] in SIGNATURES, "UNSUPPORTED_IDENTITY")
    return out


def derive_key(version: int, salt: bytes, aad: bytes, password: str | None = None) -> bytes:
    require(version in (1, 2, 3) and len(salt) == 16)
    label = b"v1" if version == 1 else b"v2"
    ikm = ROOT_KEY
    if password:
        require(isinstance(password, str), "INVALID_PASSWORD")
        # JNI GetStringChars exposes UTF-16 code units; preserve surrogate pairs.
        encoded = password.encode("utf-16-be", errors="surrogatepass")
        require(len(encoded) <= 8192, "INVALID_PASSWORD")
        ikm = hmac.digest(ikm, b"1FT1 password " + label + encoded, "sha256")
    prk = hmac.digest(salt, ikm, "sha256")
    return hmac.digest(prk, b"1FT1 HKDF AES-256-GCM " + label + aad + b"\x01", "sha256")


def parse_config(data: bytes) -> dict:
    r = Reader(data)
    require(r.take(4) == b"CFG1")
    version = r.number("B")
    require(version in range(1, 6), "UNSUPPORTED_PAYLOAD_VERSION")
    out = {"payloadVersion": version, "id": r.string(), "name": r.string(),
           "createdAt": r.number("q"), "message": r.string(nullable=True)}
    require(bool(out["id"]) and bool(out["name"]))
    mask = r.number("i") if version >= 2 else -1
    require(-1 <= mask <= 511)
    out["fieldLockMask"] = None if mask == -1 else mask
    out["ssh"] = ({"host": r.string(), "port": r.number("i"), "username": r.string(),
                   "password": r.string()} if r.boolean() else None)
    out["inject"] = ({"mode": r.choice(("DIRECT", "SSH_PAYLOAD", "PROXY", "PROXY_SNI", "WILDCARD")),
                      "payload": r.string(nullable=True), "proxyHost": r.string(nullable=True),
                      "proxyPort": r.number("i"), "sni": r.string(nullable=True),
                      "wildcardHost": r.string(nullable=True)} if r.boolean() else None)
    if out["inject"] is not None and out["inject"]["proxyPort"] == -1:
        out["inject"]["proxyPort"] = None
    out["dns"] = ({"primary": r.string(), "secondary": r.string()} if r.boolean() else None)
    xray = None
    if r.boolean():
        xray = {"protocol": r.choice(TYPES[1:]), "host": r.string(), "port": r.number("i"),
                "uuid": r.string(nullable=True), "password": r.string(nullable=True),
                "security": r.choice(("TLS", "NONE", "REALITY")),
                "network": r.choice(("WS", "GRPC", "RAW", "XHTTP", "HTTPUPGRADE"))}
        for key in ("path", "serviceName", "sni", "hostHeader", "wildcardHost"):
            xray[key] = r.string(nullable=True)
        xray["allowInsecure"] = r.boolean() if version >= 3 else False
        xray["alpn"] = r.string(nullable=True) if version >= 3 else None
        for key in ("flow", "fingerprint", "realityPublicKey", "shortId", "spiderX"):
            xray[key] = r.string(nullable=True) if version >= 4 else None
        xray["mode"] = r.string(nullable=True) if version >= 5 else None
    out["xray"] = xray
    r.end()
    return out


def decode(data: bytes | str, *, password: str | None = None) -> dict:
    require(password is None or isinstance(password, str), "INVALID_PASSWORD")
    raw = unwrap(data)
    r = Reader(raw)
    require(r.take(4) == b"1FT1")
    version = r.number("B")
    require(version in (1, 2, 3), "UNSUPPORTED_VERSION")
    require(r.take(3) == b"\x01\x01\x00")
    salt, nonce = r.take(16), r.take(12)
    aad_len, cipher_len = r.number("I"), r.number("I")
    require(aad_len <= 1024 and 16 <= cipher_len <= 4 * 1024 * 1024 + 16)
    aad, ciphertext = r.take(aad_len), r.take(cipher_len)
    r.end()
    metadata = parse_aad(aad, version)
    if metadata["lockMode"] == 2 and not password:
        raise DecodeError("PASSWORD_REQUIRED")
    key = derive_key(version, salt, aad, password if metadata["lockMode"] == 2 else None)
    try:
        aes = AES.new(key, AES.MODE_GCM, nonce=nonce, mac_len=16)
        aes.update(aad)
        plaintext = aes.decrypt_and_verify(ciphertext[:-16], ciphertext[-16:])
    except ValueError as error:
        raise DecodeError("AUTH_FAILED") from error
    config = parse_config(plaintext)
    require(metadata["createdAt"] is None or metadata["createdAt"] == config["createdAt"])
    section = config["ssh"] if metadata["configType"] == "SSH" else config["xray"]
    require(section is not None)
    if metadata["configType"] != "SSH":
        require(section["protocol"] == metadata["configType"])
    metadata.update(authenticated=True, algorithm="AES-256-GCM", kdf="HKDF-SHA256")
    return {"application": "1FTunnel", "format": "1FT1", "metadata": metadata,
            "config": config, "isPartial": False}

#!/usr/bin/env python3
"""FlexNet V2.3 B42 / V2.4 B46: FLXCFG v5/v6 and protected fields.

Offline mode 1 and FBS1 catalogs use client format material. Online mode 2
requires the file key obtained through the issuer's authorized workflow.
This module never makes network requests or fabricates attestation/grants.
"""
from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import hmac
import json
import math
import re
import struct
import sys
import zipfile
import zlib
from pathlib import Path
from typing import Any
from xml.etree import ElementTree as ET

from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Hash import SHA1, SHA256
from Crypto.PublicKey import RSA
from Crypto.Signature.pss import MGF1

MAX_INPUT = 2 * 1024 * 1024
MAX_XML = 4 * 1024 * 1024
MAX_CATALOG = 128 * 1024
CLIENT_BUILD = 46
MAX_GRANT_CAPTURE = 2048
GRANT_SCHEMA = "flexnet-v5-authorized-grant/1"
MAGIC = b"FLXCFG"
WRAP_ROOT = bytes.fromhex("09c76c0cea3739ed9aac7fb157978b4ce701d81194f7730e45c1a69750dcfd6b")
WRAP_LABEL = b"FlexNet/v5/offline/wrap/generation-1"
FIELD_LABEL = b"FlexNet/inner-field/v1/generation-1"
FIELD_MAGIC = b"FLXFLD\x01\x01"
PROTECTED_FIELDS = frozenset(("customSni", "proxyPayload"))
CATALOG_PASSWORD = b"cinbdf665$4"


class DecodeError(ValueError):
    def __init__(self, code: str, message: str):
        self.code = code
        super().__init__(message)


def _bounded(data: bytes, limit: int | None = None) -> bytes:
    if limit is None:
        limit = MAX_INPUT
    if not isinstance(data, bytes) or not data:
        raise DecodeError("FORMAT_ERROR", "Expected non-empty binary input.")
    if len(data) > limit:
        raise DecodeError("SIZE_LIMIT", "Input exceeds its size limit.")
    return data


def inspect_profile(data: bytes, *, client_build: int = CLIENT_BUILD) -> dict[str, Any]:
    _bounded(data)
    if not data.startswith(MAGIC):
        raise DecodeError("FORMAT_ERROR", "Missing FLXCFG header.")
    if len(data) < 7:
        raise DecodeError("TRUNCATED", "Missing FLXCFG version.")
    version = data[6]
    if version not in (5, 6):
        raise DecodeError("UNSUPPORTED_VERSION", "This reader handles v5/v6; use flex.py for v1-v4.")
    if len(data) < 13:
        raise DecodeError("TRUNCATED", "Incomplete FLXCFG prefix.")
    mode, suite = data[7:9]
    if mode not in ((1, 2) if version == 5 else (1,)):
        raise DecodeError("UNSUPPORTED_MODE", "Unknown FLXCFG mode.")
    if suite != 1:
        raise DecodeError("UNSUPPORTED_SUITE", "Unknown FLXCFG crypto suite.")
    minimum = struct.unpack_from(">I", data, 9)[0]
    if type(client_build) is not int or not (44 if version == 6 else 1) <= minimum <= client_build:
        raise DecodeError("MINIMUM_BUILD", "Unsupported minimum client build.")
    header_size = 141 if version == 5 and mode == 1 else 45
    if len(data) < header_size + 16:
        raise DecodeError("TRUNCATED", "Missing v5 header or authentication tag.")
    if version == 5 and mode == 1 and struct.unpack_from(">I", data, 13)[0] != 1:
        raise DecodeError("UNSUPPORTED_GENERATION", "Unknown offline wrapping generation.")
    payload_size = struct.unpack_from(">I", data, header_size - 4)[0]
    if payload_size < 16 or payload_size != len(data) - header_size:
        raise DecodeError("TRUNCATED", "Payload length does not match the file.")
    return {"format": f"FLXCFG-v{version}", "mode": "device-offline" if version == 6 else "offline" if mode == 1 else "online",
            "minimumClientBuild": minimum, "cryptoSuite": suite,
            "headerBytes": header_size, "encryptedPayloadBytes": payload_size,
            "requiresAuthorizedFileKey": mode == 2,
            "requiresAuthorizedOfflineKey": version == 6}


def _open(key: bytes, nonce: bytes, body: bytes, aad: bytes) -> bytes:
    if not isinstance(key, bytes) or len(key) != 32:
        raise DecodeError("KEY_FORMAT", "Expected a 32-byte AES key.")
    if len(nonce) != 12 or len(body) < 16:
        raise DecodeError("TRUNCATED", "Invalid nonce or missing GCM tag.")
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce, mac_len=16)
    cipher.update(aad)
    try:
        return cipher.decrypt_and_verify(body[:-16], body[-16:])
    except ValueError:
        raise DecodeError("AUTH_FAILED", "GCM authentication failed; check the key and file integrity.") from None


def _hkdf(root: bytes, salt: bytes, info: bytes) -> bytes:
    extracted = hmac.digest(salt, root, "sha256")
    return hmac.digest(extracted, info + b"\x01", "sha256")


def file_key_from_grant(data: bytes, grant: bytes, challenge: bytes) -> bytes:
    """Validate an already unwrapped import grant using B46's native bindings.

    This does not authenticate a server signature or obtain authorization. The
    official app unwraps the grant with its non-exportable Keystore RSA key.
    AES-GCM verification is still required before exposing any profile data.
    """
    info = inspect_profile(data)
    if info["format"] != "FLXCFG-v5" or info["mode"] != "online":
        raise DecodeError("GRANT_FORMAT", "An import grant requires a v5 online profile.")
    if not isinstance(grant, bytes) or len(grant) != 117:
        raise DecodeError("GRANT_FORMAT", "Expected the 117-byte unwrapped import grant, not wrappedGrant.")
    if not isinstance(challenge, bytes) or len(challenge) != 32:
        raise DecodeError("GRANT_FORMAT", "Expected the original 32-byte operation challenge.")
    bindings = ((grant[32:48], data[13:29]),
                (grant[48:80], hashlib.sha256(data).digest()),
                (grant[80:112], challenge), (grant[112:116], data[9:13]))
    if any(not hmac.compare_digest(actual, expected) for actual, expected in bindings) or grant[116] != 2:
        raise DecodeError("GRANT_BINDING", "Import grant does not match the file, challenge, build or operation.")
    return grant[:32]


def file_key_from_grant_capture(data: bytes, capture: bytes) -> bytes:
    """Read the small local capture produced during an authorized app import."""
    obj = _json(_bounded(capture, MAX_GRANT_CAPTURE))
    if (not isinstance(obj, dict)
            or set(obj) != {"schema", "fileSha256", "challengeBase64", "grantBase64"}
            or obj["schema"] != GRANT_SCHEMA
            or not isinstance(obj["fileSha256"], str)
            or not re.fullmatch(r"[0-9a-f]{64}", obj["fileSha256"])):
        raise DecodeError("GRANT_FORMAT", "Invalid authorized import capture.")
    _bounded(data)
    if not hmac.compare_digest(obj["fileSha256"], hashlib.sha256(data).hexdigest()):
        raise DecodeError("GRANT_BINDING", "Import capture belongs to a different encrypted file.")
    fields = []
    for name, size in (("challengeBase64", 32), ("grantBase64", 117)):
        value = obj[name]
        if not isinstance(value, str) or len(value) != ((size + 2) // 3) * 4:
            raise DecodeError("GRANT_FORMAT", "Invalid capture field length.")
        try:
            raw = base64.b64decode(value, validate=True)
        except (binascii.Error, ValueError):
            raise DecodeError("GRANT_FORMAT", "Invalid capture Base64.") from None
        if len(raw) != size or base64.b64encode(raw).decode("ascii") != value:
            raise DecodeError("GRANT_FORMAT", "Expected canonical capture Base64.")
        fields.append(raw)
    return file_key_from_grant(data, fields[1], fields[0])


def read_grant_capture(path: Path) -> bytes:
    with path.open("rb") as handle:
        return _bounded(handle.read(MAX_GRANT_CAPTURE + 1), MAX_GRANT_CAPTURE)


def decrypt_profile_xml(data: bytes, *, file_key: bytes | None = None,
                        offline_key: bytes | None = None,
                        grant_capture: bytes | None = None,
                        client_build: int = CLIENT_BUILD) -> str:
    info = inspect_profile(data, client_build=client_build)
    if grant_capture is not None:
        if file_key is not None or offline_key is not None:
            raise DecodeError("KEY_OPTIONS", "Use the import capture without other key options.")
        file_key = file_key_from_grant_capture(data, grant_capture)
    if info["mode"] == "device-offline":
        if offline_key is None:
            raise DecodeError("OFFLINE_KEY_REQUIRED", "This v6 export requires its authorized offline setup key; it is stored in Android Keystore, not in the file or APK.")
        inner = _open(offline_key, data[29:41], data[45:], data[:45])
        if not inner.startswith(MAGIC + b"\x05\x01"):
            raise DecodeError("FORMAT_ERROR", "Expected a v5 offline container inside v6.")
        return decrypt_profile_xml(inner, client_build=client_build)
    if info["mode"] == "offline":
        wrap_key = _hkdf(WRAP_ROOT, data[33:65], WRAP_LABEL + data[:33])
        key = _open(wrap_key, data[65:77], data[77:125], data[:77])
        compressed = _open(key, data[125:137], data[141:], data[:141])
    else:
        if file_key is None:
            raise DecodeError("ONLINE_AUTH_REQUIRED", "This online export requires an authorized server-issued file key; it is not stored in the file or APK.")
        compressed = _open(file_key, data[29:41], data[45:], data[:45])
    try:
        inflater = zlib.decompressobj(31)
        plain = inflater.decompress(compressed, MAX_XML + 1)
    except zlib.error:
        raise DecodeError("INVALID_GZIP", "Authenticated profile is not valid gzip.") from None
    if len(plain) > MAX_XML or inflater.unconsumed_tail:
        raise DecodeError("SIZE_LIMIT", "Decompressed XML exceeds 4 MiB.")
    if not inflater.eof or inflater.unused_data:
        raise DecodeError("INVALID_GZIP", "Truncated gzip stream or unexpected trailing data.")
    try:
        return plain.decode("utf-8")
    except UnicodeError:
        raise DecodeError("INVALID_XML", "Authenticated XML is not UTF-8.") from None


def _unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise DecodeError("INVALID_JSON", "Duplicate JSON keys are not supported.")
        result[key] = value
    return result


def _constant(value: str) -> Any:
    raise DecodeError("INVALID_JSON", "Non-finite JSON numbers are not supported.")


def _json(data: bytes | str) -> Any:
    try:
        text = data.decode("utf-8") if isinstance(data, bytes) else data
        obj = json.loads(text, object_pairs_hook=_unique, parse_constant=_constant)
        stack, count = [(obj, 0)], 0
        while stack:
            value, depth = stack.pop()
            count += 1
            if count > 200_000 or depth > 64:
                raise DecodeError("STRUCTURE_LIMIT", "JSON structure exceeds its limits.")
            if isinstance(value, dict):
                stack.extend((item, depth + 1) for item in value.values())
                stack.extend((key, depth + 1) for key in value)
            elif isinstance(value, list):
                stack.extend((item, depth + 1) for item in value)
            elif isinstance(value, str):
                value.encode("utf-8")
            elif isinstance(value, float) and not math.isfinite(value):
                raise ValueError
            if count + len(stack) > 200_000:
                raise DecodeError("STRUCTURE_LIMIT", "JSON structure exceeds its limits.")
        return obj
    except DecodeError:
        raise
    except (UnicodeError, ValueError, RecursionError):
        raise DecodeError("INVALID_JSON", "Expected valid UTF-8 JSON.") from None


def _protected_properties(props: dict[str, str]) -> dict[str, str] | None:
    if "file.routeData" not in props and "file.routeFields" not in props:
        return None
    if props.get("file.routeFields") != "1" or "file.routeData" not in props:
        raise DecodeError("INVALID_FIELD", "Missing protected field metadata.")
    document = _json(props["file.routeData"])
    if (not isinstance(document, dict) or set(document) != {"v", "fields"}
            or type(document["v"]) is not int or document["v"] != 1
            or not isinstance(document["fields"], dict)
            or not set(document["fields"]) <= PROTECTED_FIELDS):
        raise DecodeError("INVALID_FIELD", "Invalid protected field document.")
    fields = document["fields"]
    opened = {}
    for name in PROTECTED_FIELDS:
        if name not in fields:
            if props.get(name, ""):
                raise DecodeError("INVALID_FIELD", "Missing protected field envelope.")
            continue
        entry = fields[name]
        if not isinstance(entry, dict) or set(entry) != {"a", "c"}:
            raise DecodeError("INVALID_FIELD", "Invalid protected field entry.")
        alias = entry["a"]
        if (not isinstance(alias, str) or not alias or len(alias.encode("utf-16-le")) > 400
                or alias != props.get(name)):
            raise DecodeError("INVALID_FIELD", "Protected field binding mismatch.")
        binding = ("FlexNet/inner-field/v1\0" + name + "|" + alias).encode("utf-8")
        if len(binding) > 512:
            raise DecodeError("INVALID_FIELD", "Protected field binding is too large.")
        raw = _base64_field(entry["c"], MAX_INPUT)
        if base64.b64encode(raw).decode("ascii") != entry["c"]:
            raise DecodeError("INVALID_FIELD", "Noncanonical protected field encoding.")
        if (len(raw) <= 76 or raw[:8] != FIELD_MAGIC or struct.unpack_from(">I", raw, 8)[0] != 43
                or struct.unpack_from(">I", raw, 56)[0] != len(raw) - 60):
            raise DecodeError("INVALID_FIELD", "Invalid protected field header or length.")
        key = _hkdf(WRAP_ROOT, raw[12:44], FIELD_LABEL + binding)
        plain = _open(key, raw[44:56], raw[60:], raw[:60] + binding)
        try:
            opened[name] = plain.decode("utf-8")
        except UnicodeError:
            raise DecodeError("INVALID_FIELD", "Protected field is not UTF-8.") from None
    return opened


def decode_profile(data: bytes, *, file_key: bytes | None = None,
                   offline_key: bytes | None = None,
                   grant_capture: bytes | None = None) -> dict[str, Any]:
    xml = decrypt_profile_xml(data, file_key=file_key, offline_key=offline_key, grant_capture=grant_capture)
    # The app uses java.util.Properties, not an arbitrary XML document.
    if re.search(r"<!ENTITY\b|<!DOCTYPE[^>]*\[", xml, re.I):
        raise DecodeError("INVALID_XML", "XML entity declarations are not supported.")
    try:
        root = ET.fromstring(xml)
    except (ET.ParseError, RecursionError):
        raise DecodeError("INVALID_XML", "Authenticated content is not valid XML.") from None
    if root.tag != "properties":
        raise DecodeError("INVALID_XML", "Expected an XML properties document.")
    props: dict[str, str] = {}
    comments: list[str] = []
    for entry in root:
        if entry.tag == "comment":
            comments.append(entry.text or "")
        elif entry.tag == "entry" and isinstance(entry.get("key"), str) and len(entry) == 0:
            key = entry.get("key")
            if key in props:
                raise DecodeError("INVALID_XML", "Duplicate XML property keys.")
            props[key] = entry.text or ""
        else:
            raise DecodeError("INVALID_XML", "Unexpected XML property structure.")
    result: dict[str, Any] = {"app": "FlexNet", "format": f"FLXCFG-v{data[6]}", "rawProperties": props}
    opened = _protected_properties(props)
    if opened is not None:
        result["protectedFields"] = opened
        result["decodedProperties"] = {**props, **opened}
    if comments:
        result["xmlComments"] = comments
    embedded = {}
    for key, value in props.items():
        if value.lstrip().startswith(("{", "[")):
            try:
                embedded[key] = _json(value)
            except DecodeError:
                pass  # Preserve the exact property even if it is ordinary text.
    if embedded:
        result["embeddedJson"] = embedded
    return result


def _catalog_document(data: bytes) -> dict[str, Any]:
    obj = _json(data)
    if (not isinstance(obj, dict) or not isinstance(obj.get("servers"), list)
            or any(not isinstance(server, dict) for server in obj["servers"])):
        raise DecodeError("WRONG_DOCUMENT", "Expected a server catalog with an array of objects.")
    return obj


def decode_builtin_catalog(data: bytes) -> dict[str, Any]:
    _bounded(data, MAX_CATALOG)
    if not data.startswith(b"FBS1") or len(data) < 32:
        raise DecodeError("FORMAT_ERROR", "Expected an FBS1 builtin catalog.")
    key = hashlib.sha256(b"flexnet-builtin-servers-v1\0" + CATALOG_PASSWORD).digest()
    return _catalog_document(_open(key, data[4:16], data[16:], b"FBS1"))


def _base64_field(value: Any, limit: int) -> bytes:
    if not isinstance(value, str) or len(value) > ((limit + 2) // 3) * 4:
        raise DecodeError("FORMAT_ERROR", "Invalid catalog envelope field.")
    try:
        value = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError):
        raise DecodeError("FORMAT_ERROR", "Invalid catalog envelope Base64.") from None
    if len(value) > limit:
        raise DecodeError("SIZE_LIMIT", "Catalog envelope field exceeds its size limit.")
    return value


def decode_server_envelope(data: bytes, private_key: bytes | None = None) -> dict[str, Any]:
    _bounded(data)
    envelope = _json(data)
    if not isinstance(envelope, dict) or envelope.get("ok") is not True or envelope.get("mode") != "flexnet-servers-v1":
        raise DecodeError("FORMAT_ERROR", "Expected a flexnet-servers-v1 response envelope.")
    if private_key is None:
        raise DecodeError("PRIVATE_KEY_REQUIRED", "The remote catalog requires the private RSA key created for that authorized request.")
    if not isinstance(private_key, bytes) or len(private_key) > 64 * 1024:
        raise DecodeError("KEY_FORMAT", "Invalid RSA private key size or type.")
    try:
        rsa = RSA.import_key(private_key)
        if not rsa.has_private() or not 2048 <= rsa.size_in_bits() <= 4096:
            raise ValueError
    except (ValueError, IndexError, TypeError):
        raise DecodeError("KEY_FORMAT", "Expected a 2048-4096-bit RSA private key.") from None
    wrapped = _base64_field(envelope.get("encryptedKey"), 512)
    nonce = _base64_field(envelope.get("nonce"), 12)
    ciphertext = _base64_field(envelope.get("ciphertext"), MAX_INPUT)
    aad = envelope.get("aad")
    if not isinstance(aad, str) or len(aad) > 4096:
        raise DecodeError("FORMAT_ERROR", "Invalid catalog AAD.")
    try:
        key = PKCS1_OAEP.new(rsa, hashAlgo=SHA256, mgfunc=lambda seed, n: MGF1(seed, n, SHA1)).decrypt(wrapped)
        aad_bytes = aad.encode("utf-8")
    except (ValueError, UnicodeError):
        raise DecodeError("AUTH_FAILED", "Catalog RSA key unwrapping failed.") from None
    return _catalog_document(_open(key, nonce, ciphertext, aad_bytes))


def builtin_from_apk(path: Path) -> bytes:
    try:
        with zipfile.ZipFile(path) as archive:
            info = archive.getinfo("assets/builtin_servers.dat")
            if info.file_size > MAX_CATALOG:
                raise DecodeError("SIZE_LIMIT", "Builtin catalog exceeds 128 KiB.")
            with archive.open(info) as handle:
                data = handle.read(MAX_CATALOG + 1)
    except (zipfile.BadZipFile, KeyError):
        raise DecodeError("FORMAT_ERROR", "APK has no readable assets/builtin_servers.dat.") from None
    return _bounded(data, MAX_CATALOG)


def decode(data: bytes, *, file_key: bytes | None = None,
           offline_key: bytes | None = None,
           grant_capture: bytes | None = None,
           private_key: bytes | None = None) -> dict[str, Any]:
    _bounded(data)
    if data.startswith(MAGIC):
        return decode_profile(data, file_key=file_key, offline_key=offline_key, grant_capture=grant_capture)
    if grant_capture is not None:
        raise DecodeError("GRANT_FORMAT", "An import capture requires a v5 online profile.")
    if data.startswith(b"FBS1"):
        return decode_builtin_catalog(data)
    return decode_server_envelope(data, private_key=private_key)


def run(file_bytes: bytes, **kwargs: Any) -> str | None:
    try:
        return json.dumps(decode(file_bytes, **kwargs), ensure_ascii=False, indent=2) + "\n"
    except DecodeError:
        return None


def read_key_file(path: Path) -> bytes:
    with path.open("rb") as handle:
        data = handle.read(129)
    if len(data) == 32:
        return data
    if re.fullmatch(rb"[0-9A-Fa-f]{64}", data.strip()):
        return bytes.fromhex(data.strip().decode("ascii"))
    raise DecodeError("KEY_FORMAT", "Key file must contain 32 bytes or 64 hex digits.")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="FlexNet B42/B46 v5/v6 and server catalog decoder (offline)")
    parser.add_argument("file", type=Path)
    parser.add_argument("-o", "--output", type=Path)
    parser.add_argument("--builtin-catalog", action="store_true", help="Read FBS1 catalog from the supplied APK")
    parser.add_argument("--inspect", action="store_true", help="Inspect v5/v6 header; no plaintext is decrypted")
    parser.add_argument("--file-key-file", type=Path, help="Authorized online file key: 32 binary bytes or 64 hex digits")
    parser.add_argument("--grant-capture", type=Path, help="Local JSON capture from a successful authorized v5 import")
    parser.add_argument("--offline-key-file", type=Path, help="Authorized v6 offline setup key: 32 binary bytes or 64 hex digits")
    parser.add_argument("--rsa-key-file", type=Path, help="Private RSA key for a saved authorized catalog response")
    args = parser.parse_args(argv)
    if args.inspect and args.builtin_catalog:
        parser.error("--inspect and --builtin-catalog cannot be combined")
    if args.grant_capture and any((args.inspect, args.builtin_catalog, args.file_key_file, args.offline_key_file, args.rsa_key_file)):
        parser.error("--grant-capture cannot be combined with inspection, catalog or key options")
    try:
        if args.builtin_catalog:
            raw = builtin_from_apk(args.file)
        else:
            with args.file.open("rb") as handle:
                raw = handle.read(MAX_INPUT + 1)
        file_key = read_key_file(args.file_key_file) if args.file_key_file else None
        offline_key = read_key_file(args.offline_key_file) if args.offline_key_file else None
        private_key = None
        if args.rsa_key_file:
            with args.rsa_key_file.open("rb") as handle:
                private_key = handle.read(64 * 1024 + 1)
        capture = read_grant_capture(args.grant_capture) if args.grant_capture else None
        obj = inspect_profile(raw) if args.inspect else decode(raw, file_key=file_key, offline_key=offline_key, grant_capture=capture, private_key=private_key)
        result = json.dumps(obj, ensure_ascii=False, indent=2) + "\n"
        if args.output:
            args.output.write_text(result, encoding="utf-8")
        else:
            sys.stdout.write(result)
        return 0
    except DecodeError as error:
        print(json.dumps({"error": error.code, "message": str(error)}), file=sys.stderr)
        return 1
    except OSError:
        print(json.dumps({"error": "IO_ERROR", "message": "Cannot read the input/key or write the result."}), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())

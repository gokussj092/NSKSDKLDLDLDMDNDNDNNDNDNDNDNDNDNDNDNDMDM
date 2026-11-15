#!/usr/bin/env python3
"""Offline adapters for the owner's supplied codecs, never their network/CLI APIs.

One child process loads one fixed codec. Original scripts stay unchanged.
"""
from __future__ import annotations
import base64
import binascii
from contextlib import contextmanager
import importlib.util
import inspect
import json
import socket
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
INVENTORY = ROOT / "cloud/web/content/supplied-integrations.json"
ITEMS = json.loads(INVENTORY.read_text())["apps"]
BY_ID = {item["id"]: item for item in ITEMS}
# Generic .js/.rj files are intentionally not guessed by extension.
FILE_ROUTES = {suffix: item["id"] for item in ITEMS if item["fileModule"]
               for suffix in item["extensions"] if suffix not in {"js", "rj", "hxt", "hexcm", "tgv"}}
TEXT_ROUTES = sorted([(prefix.lower(), item["id"]) for item in ITEMS if item["fileModule"]
                     for prefix in item["textPrefixes"] if not prefix.startswith(("http://", "https://"))],
                    key=lambda pair: -len(pair[0]))


# Content discriminators for suffixes shared by two formats (bytes only,
# never decryption). Adapted from the design in
# ~/workspace/repo-integration/discriminators/ (predicates.py).
# .hs: JK is strict Base64 with a 40-byte Tink header and segment geometry;
# RH is a SabDev:// / shanS:// share link (default: every other .hs form
# the RH reader accepts — plain JSON, sab-blob, bare XXTEA — is RH).
import re as _re


def _compact_text(contents: bytes) -> str | None:
    """UTF-8 text with all whitespace removed, or None if not UTF-8 text."""
    try:
        text = contents.decode("utf-8-sig")
    except UnicodeError:
        return None
    return "".join(text.split())


def _b64decode_strict(text: str) -> bytes | None:
    """Strict standard-Base64 decode of one token, or None."""
    if not text or len(text) % 4 == 1:
        return None
    if not _re.fullmatch(r"[A-Za-z0-9+/]+={0,2}", text):
        return None
    try:
        return base64.b64decode(text + "=" * (-len(text) % 4), validate=True)
    except (ValueError, binascii.Error):
        return None


_JK_HEADER_SIZE = 40
_JK_FIRST_CT_SEGMENT = 4096 - _JK_HEADER_SIZE  # 4056
_JK_CT_SEGMENT = 4096


def _hs_segment_fit(body: bytes) -> bool:
    """True iff `body` slices like a Tink Streaming AEAD body: first
    segment <= 4056 bytes, then 4096-byte segments, last segment 17..4096."""
    if len(body) < 17:
        return False
    rest = body[_JK_FIRST_CT_SEGMENT:]
    while len(rest) > _JK_CT_SEGMENT:
        rest = rest[_JK_CT_SEGMENT:]
    return True if not rest else 17 <= len(rest) <= _JK_CT_SEGMENT


def _is_jk_hs(contents: bytes) -> bool:
    """True for a JK VPN .hs: strict Base64 text, length 0 (mod 4),
    raw length >= 56, raw[0] == 40, and Tink segment geometry fits."""
    compact = _compact_text(contents)
    if compact is None:
        return False
    blob = _b64decode_strict(compact)
    if blob is None or len(blob) < _JK_HEADER_SIZE + 16:
        return False
    if blob[0] != _JK_HEADER_SIZE:
        return False
    return _hs_segment_fit(blob[_JK_HEADER_SIZE:])


def _is_rh_hs(contents: bytes) -> bool:
    """True for an RH Tunnel Lite exported .hs: text starting with the
    SabDev:// (server) or shanS:// (network) share-link prefix."""
    try:
        text = contents.decode("utf-8-sig").strip()
    except UnicodeError:
        return False
    return text.startswith(("SabDev://", "shanS://"))


class IntegrationError(ValueError):
    def __init__(self, code):
        super().__init__(code)
        self.code = code


def load(item, role="catalogModule"):
    folder = ROOT / "decoders/Python/apps" / item["appDir"]
    path = folder / item[role]
    if not path.is_file() or path.parent != folder or not folder.is_relative_to(ROOT / "decoders/Python/apps"):
        raise IntegrationError("ENGINE_UNAVAILABLE")
    name = "_supplied_" + item["appDir"] + "_" + role
    if name in sys.modules:
        return sys.modules[name]
    sys.path.insert(0, str(folder))  # Owner scripts import their existing siblings.
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    # These supplied standalone scripts have a pure Python RFC-9106 backend.
    # Use the repository's already pinned argon2-cffi for the SAME primitive
    # in the server adapter; keep vendor source files byte-identical. Extra
    # Argon2 secret/AD variants keep their original implementation.
    if hasattr(module, "_argon2id"):
        from argon2.low_level import hash_secret_raw, Type
        original = module._argon2id
        def argon2id(password, salt, time_cost, memory_kib, parallelism, tag_len,
                     secret=b"", ad=b"", version=0x13):
            if secret or ad:
                return original(password, salt, time_cost, memory_kib, parallelism,
                                tag_len, secret, ad, version)
            return hash_secret_raw(password, salt, time_cost, memory_kib, parallelism,
                                   tag_len, Type.ID, version)
        argon2id.__wrapped__ = original
        module._argon2id = argon2id
    return module


def deny_network(*args, **kwargs):
    raise IntegrationError("REMOTE_NETWORK_DENIED")


@contextmanager
def offline():
    # Defense in depth: a misselected vendor run() must never download anything.
    previous=(socket.socket.connect,socket.socket.connect_ex,socket.create_connection,socket.getaddrinfo)
    socket.socket.connect=socket.socket.connect_ex=socket.create_connection=socket.getaddrinfo=deny_network
    try:
        yield
    finally:
        socket.socket.connect,socket.socket.connect_ex,socket.create_connection,socket.getaddrinfo=previous


def document(value):
    if isinstance(value, bytes):
        value = value.decode("utf-8")
    if isinstance(value, str):
        value = json.loads(value)
    if not isinstance(value, (dict, list)) or not value:
        raise IntegrationError("DECODE_FAILED")
    if isinstance(value, dict) and value.get("status") == "error":
        code = value.get("code", "DECODE_FAILED")
        raise IntegrationError(code if code in {"PASSWORD_REQUIRED", "HWID_REQUIRED", "UNSUPPORTED_VERSION"} else "DECODE_FAILED")
    return value


def decode_one(item, raw):
    module = load(item)
    app = item["appDir"]
    if app in {"APNA_Tunnel_Lite", "UDP_Thunder_VPN"}:
        return document(module.decode_json_bytes(raw))
    if app == "IP_Tunnel":
        return document(module.decode_blob_text(raw.decode("utf-8")))
    if app == "CATNET_VPN":
        return document(module.run(raw))
    # Catalog entry points of the 2026-11-15 batch: these verified scripts
    # do not expose decode(), so dispatch to each script's real reader.
    # Every branch returns the catalog with all fields decrypted and no
    # download APIs in the result (owner rule 2026-11-15).
    if app == "PPH_GOOD_VPN":
        plain = module.decrypt_envelope(raw)
        if plain is None:
            raise IntegrationError("DECODE_FAILED")
        return document(module.decrypt_catalog_fields(json.loads(plain.decode("utf-8"))))
    if app == "CHN_Tunnel_Lite":
        readable, _fails = module.readable_catalog(module.decrypt_catalog_body(raw.decode("utf-8-sig")))
        return document(readable)
    if app == "ZIVPN":
        return document(module.decode_catalog(raw.decode("utf-8-sig")))
    if app == "FMT_VPN":
        return document(module.clean_catalog(module.decrypt_catalog_blob(raw.decode("utf-8-sig"))))
    if app == "HTTP_Tweak":
        # Public plain JSON (servers + tweaks); nothing to decrypt. The
        # tweaks file is legitimately {} today, so parse directly instead
        # of document(), which rejects empty documents.
        return json.loads(raw.decode("utf-8-sig"))
    if app == "RH_Tunnel_Lite":
        return document(module.parse_catalog(raw.decode("utf-8-sig")))
    if app == "JK_VPN":
        return document(module.limpiar_catalogo(module.descifrar_hs_b64(raw)))
    result = module.decode(raw.decode("utf-8-sig"))
    if app == "MM_Tunnel":
        result,stats=module.decode_fields(result,workers=2,strict=False)
        if stats["failed"]:
            result["decryptionStatus"]={"complete":False,"unresolvedFields":stats["failed"],
                                       "locations":stats["failed_fields"]}
    elif app in {"Marvs_V2Ray", "Bee_VPN", "VLX_Tunnel_VPN"}:
        # The catalog envelope opens with decode(); the protected field
        # envelopes need decode_fields (same pattern as MM_Tunnel, but
        # workers=4: 1,496 / 3,464 / 4,518 envelopes; workers=2 measured
        # 85 s / 129 s / 154 s end-to-end on a 1.5-CPU sandbox, over the
        # 120 s catalog budget — the 6-vCore worker has room for 4).
        result,stats=module.decode_fields(result,workers=4,strict=False)
        if stats["failed"]:
            result["decryptionStatus"]={"complete":False,"unresolvedFields":stats["failed"],
                                       "locations":stats["failed_fields"]}
    elif app == "PUKANG_VPN":
        result = module.decode_fields(result)
    elif app == "PNT_VPN":
        result = module.decrypt_fields(result)
    elif app == "RoVPN":
        result = module.decoded(result)
    return document(result)


def catalog(provider, payload):
    item = BY_ID[provider]
    # Multi-source catalogs preserve every source; never silently return one.
    if len(item["requests"]) > 1:
        bundle = json.loads(payload)
        expected = {r["name"] for r in item["requests"]}
        if (set(bundle) != {"kind", "providerId", "sources"} or
                bundle["kind"] != "spdecode-supplied-catalog-v1" or bundle["providerId"] != provider or
                not isinstance(bundle["sources"], dict) or set(bundle["sources"]) != expected):
            raise IntegrationError("INVALID_INPUT")
        sources = {k: base64.b64decode(v, validate=True) for k, v in bundle["sources"].items()}
        if item["appDir"] == "SLOW_DNS":
            module = load(item)
            index = module.decode_updater(sources["updater"])
            password = module.k_decrypt(index["ServerPassWD"], module.STAGE1_PASSWORD)
            url = module.k_decrypt(index["ServerLink"], password)
            if url != item["requests"][1]["url"]:
                raise IntegrationError("REMOTE_RESPONSE_INVALID")
            return document(module.decode_catalog_body(sources["servers"], password))
        if item["appDir"] == "PNT_VPN":
            index = json.loads(sources["updater"])
            if index.get("fileUrl") != item["requests"][1]["url"]:
                raise IntegrationError("REMOTE_RESPONSE_INVALID")
            return decode_one(item, sources["servers"])
        return {"provider": provider, "complete": True,
                "catalogs": {name: decode_one(item, data) for name, data in sources.items()}}
    return decode_one(item, payload)


def file_decode(provider, raw, credentials=None):
    item = BY_ID[provider]
    module = load(item, "fileModule")
    app = item["appDir"]
    if app in {"Binke_Volt", "OSP_Tunnel", "Zam_VIP_NET"}:
        return document(module.decode_text(raw.decode("utf-8-sig")))
    if app == "OneFTunnel":
        if raw.startswith((b"1FTnl.",b"1FT1.",b"1ftunnel://1FTnl/",b"1ftunnel://1FT1/")):
            from decoders.Python.apps.OneFTunnel.file_decoder import run
            return document(run(raw,password=(credentials or {}).get("password")))
        return document(module.run(raw, password=(credentials or {}).get("password")))
    if app == "MM_Tunnel":
        # Existing .mmt imports already decrypt their nested fields. The
        # supplied standalone file reader opens only the outer envelope;
        # retain the complete compatible file codec and its historical route.
        from decoders.Python.apps.MM_Tunnel.file_decoder import run
        return document(run(raw))
    if app == "V2Box":
        text = raw.decode("utf-8-sig").strip()
        if text.lower().startswith("v2box://"):
            text = text[len("v2box://"):]
            if text.startswith("locked="):
                text = text[len("locked="):]
            if not text.startswith("{"):
                text = base64.b64decode(text + "=" * (-len(text) % 4), validate=True).decode("utf-8")
            raw = text.encode("utf-8")
        envelope = json.loads(raw)
        if "version" not in envelope:
            from cloud.workers.python.v2box_bridge import process
            code, result = process(raw, credentials or {})
            if code != "OK":
                raise IntegrationError(code)
            return document(result)
        return document(module.decode_file(raw, password=(credentials or {}).get("password")))
    # File entry points of the 2026-11-15 batch: these verified scripts do
    # not expose decode(), so dispatch to each script's real reader.
    if app == "RH_Tunnel_Lite":
        # .hs export is the SabDev:// / shanS:// share link (or plain JSON /
        # sab-blob); decode_text returns (kind, obj).
        _kind, obj = module.decode_text(raw.decode("utf-8-sig"))
        return document(obj)
    if app == "JK_VPN":
        # .hs is a Base64 Tink Streaming AEAD byte string; the catalog
        # module (imported by the file script) decrypts and cleans it.
        return document(module.limpiar_catalogo(module.descifrar_hs_b64(raw)))
    if app == "WyrVPN":
        # No decode(): open_binary covers raw WVE1, raw v01 and wyrvpn:// text.
        try:
            profiles, _variant = module.open_binary(raw, password=(credentials or {}).get("password"))
        except ValueError as exc:
            code = getattr(exc, "code", None)
            if code in {"PASSWORD_REQUIRED", "HWID_REQUIRED", "HWID_PASSWORD_REQUIRED",
                        "WRONG_PASSWORD", "AUTH_FAILED"}:
                raise IntegrationError(code)
            # Plain decode failure: the historic C0 wyrvpn reader owns the
            # old-key v01 envelopes (same _C8_GENERIC_FALLBACK semantics as
            # .wyr files; this also keeps old wyrvpn:// text links working).
            from decoders.Python import wyrvpn as _legacy_wyrvpn
            legacy = _legacy_wyrvpn.run(raw)
            if legacy is None:
                raise IntegrationError("DECODE_FAILED")
            return document(legacy)
        return document(profiles)
    if app == "TCx_Tunnel":
        # No decode(): decrypt_text opens tcxtunnelplus:// text or a bare cipher.
        try:
            return document(module.decrypt_text(raw.decode("utf-8-sig")))
        except ValueError:
            # Plain failure: the historic RENZ reader owns the old-key
            # tcxtunnelplus:// envelopes (same fallback semantics as .tcx files).
            from decoders.Python import renz as _legacy_renz
            legacy = _legacy_renz.decode_text(raw.decode("utf-8-sig"))
            if legacy is None:
                raise IntegrationError("DECODE_FAILED")
            return document(legacy)
    if app == "CHN_Tunnel_Lite":
        # No decode(): a chntunnellite:// link opens with open_link, which
        # returns (network, state, detail). PIN-protected networks report
        # PASSWORD_REQUIRED; the engine/text password gates do not forward a
        # PIN for this prefix yet (pending decision, see report).
        network, state, _detail = module.open_link(
            raw.decode("utf-8-sig").strip(), pin=(credentials or {}).get("password"))
        if state == "OK":
            return document(network)
        if state == "PIN_REQUIRED":
            raise IntegrationError("PASSWORD_REQUIRED")
        raise IntegrationError("DECODE_FAILED")
    if app == "EUT_VPN":
        # No decode(): import_text returns (kind, obj); obj is None when the
        # blob does not open with the new key. Historic blobs never reach
        # this branch: engine.py routes them to the frozen C0 reader.
        _kind, obj = module.import_text(raw.decode("utf-8-sig"))
        if obj is None:
            raise IntegrationError("DECODE_FAILED")
        return document(obj)
    fn = module.decode
    allowed = inspect.signature(fn).parameters
    kwargs = {key: value for key, value in (credentials or {}).items() if key in allowed}
    if app == "SNI_Tunnel":
        raw = raw.decode("utf-8-sig")
    result=document(fn(raw, **kwargs))
    return result


def text_decode(text, password=None):
    for prefix, provider in TEXT_ROUTES:
        if text.lower().startswith(prefix):
            value=file_decode(provider,text.encode("utf-8"),{"password":password} if password else {})
            if prefix in {"osp://","osptunnel://","letsvpngo://","hamaratnl://"}:
                # Preserve the existing protocol envelope and deeper legacy
                # HAMARA SNI transform, while using the supplied OSP/Lets codec
                # for its complete decoded configuration.
                import importlib
                for name in ("decoders.Python.renz","decoders.Python.xor_family"):
                    try:
                        legacy=importlib.import_module(name).decode_text(text)
                        if not legacy:
                            continue
                        legacy=document(legacy)
                        if prefix=="hamaratnl://":
                            value=legacy
                        elif isinstance(legacy,dict) and set(legacy)=={"application","protocol","config"}:
                            value={**legacy,"config":value}
                        break
                    except (ValueError,TypeError):
                        continue
            return json.dumps(value,ensure_ascii=False,indent=2)
    return None


@offline()
def main():
    if len(sys.argv) != 2:
        return 2
    try:
        path = Path(sys.argv[1])
        provider = FILE_ROUTES.get(path.suffix[1:])
        if provider is None:
            raise IntegrationError("UNSUPPORTED_FORMAT")
        raw_credentials = sys.stdin.buffer.read(8193)
        if len(raw_credentials) > 8192:
            raise IntegrationError("INVALID_CREDENTIALS")
        credentials = json.loads(raw_credentials) if raw_credentials else {}
        raw = path.read_bytes()
        if path.suffix[1:] == "hs":
            # Shared suffix: JK by content (40-byte Tink header + segment
            # geometry), RH by default (links, plain JSON, sab-blob, bare
            # XXTEA are all RH). On a plain DECODE_FAILED only, try the
            # other provider once (covers the ~0.4% bare-XXTEA collision
            # and undocumented RH wrappers); never retry credential,
            # version or protection errors.
            provider = "jk-vpn" if _is_jk_hs(raw) else "rh-tunnel-lite"
            try:
                result = file_decode(provider, raw, credentials)
            except IntegrationError as exc:
                if exc.code != "DECODE_FAILED":
                    raise
                other = "rh-tunnel-lite" if provider == "jk-vpn" else "jk-vpn"
                result = file_decode(other, raw, credentials)
        else:
            result = file_decode(provider, raw, credentials)
        sys.stdout.write(json.dumps(result, ensure_ascii=False, indent=2))
        return 0
    except Exception as exc:
        code = getattr(exc, "code", "DECODE_FAILED")
        aliases = {"WRONG_PASSWORD": "AUTH_FAILED", "BAD_PASSWORD": "AUTH_FAILED", "DEVICE_KEY_REQUIRED": "PRIVATE_KEY_REQUIRED"}
        code = aliases.get(code, code)
        if code not in {"PASSWORD_REQUIRED", "HWID_REQUIRED", "HWID_PASSWORD_REQUIRED", "AUTH_FAILED",
                        "PRIVATE_KEY_REQUIRED", "UNSUPPORTED_VERSION", "INVALID_CREDENTIALS", "UNSUPPORTED_FORMAT"}:
            code = "DECODE_FAILED"
        sys.stdout.write(json.dumps({"workerError": code}))
        return 3


if __name__ == "__main__":
    raise SystemExit(main())

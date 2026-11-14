#!/usr/bin/env python3
"""Offline adapters for the owner's supplied codecs, never their network/CLI APIs.

One child process loads one fixed codec. Original scripts stay unchanged.
"""
from __future__ import annotations
import base64
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
    result = module.decode(raw.decode("utf-8-sig"))
    if app == "MM_Tunnel":
        result,stats=module.decode_fields(result,workers=2,strict=False)
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
        result = file_decode(provider, path.read_bytes(), credentials)
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

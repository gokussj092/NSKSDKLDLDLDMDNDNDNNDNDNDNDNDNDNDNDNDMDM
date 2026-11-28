#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""V2Ray Injector 1.4.2 (tech.docnet.xraytunnel, versionCode 16) -- catalog +
file decoders. SP-DECODE catalog batch 18. Verified live 2026-11-28.

App: "v2ray injector" (V2K), an Xray-core VPN client. Package
tech.docnet.xraytunnel. All app code lives in classes12.dex; all native
libraries live in split_config.arm64_v8a.apk (libgojni.so = Xray core,
libhev-socks5-tunnel.so, libsigner.so, ...). The base APK has NO native
libraries; the .es / .xhdpi splits have none either.

Catalog (live, SecureConfigFetcher.kt):
  GET https://xraytunnel-config.admin6795.workers.dev/api/config
  Headers (exact): Accept: application/json
                   User-Agent: XrayTunnel/1.0
                   X-API-KEY: a112be46639d73d581813ecd2a382c6b
  Connect/read timeout 10 s, 3 attempts, delay (attempt+1)*1000 ms.
  Response JSON: {"servers": "<enc>", "configs": "<enc>", "version": "1.0.0",
                  "catalogSource": "manager",
                  "catalogReleaseId": "rel_..._...",
                  "catalogSnapshotId": "cat_...",
                  "timestamp": <ms epoch>}
  The /api/store endpoint on the same worker is only a community listing
  board (empty at check time); it carries no servers and is NOT a catalog.

Envelope encryption (CryptoHelper.kt, AES/GCM/NoPadding, tag 128 bit):
  format: base64(IV 12 B) + "." + base64(ciphertext + 16 B GCM tag)
  key (32 B, hardcoded in CryptoHelper.getKey()):
      4a7b9c2d3e5f6a8b1c0d2e4f6789abcd0123456789abcdef0123456789abcdef
  Both "servers" and "configs" use this envelope. The same envelope is
  used for the bundled fallback assets (assets/servers.enc = 913 servers,
  assets/configs.enc = 59 configs, older snapshot) and for the on-disk
  cache (config_cache.enc), and for encrypted .v2k files (see below).
  No per-field encryption exists: after the envelope is opened, every
  field is plaintext. Server "uuid" IS the credential used verbatim by
  the Xray builder (VLESS/VMess UUID, Shadowsocks password -- Outline
  style base64 keys are used as-is -- or Trojan password); it is not a
  second encryption layer. The 13 official no-protocol servers use the
  shared uuid "cassianodev".

Servers (live 2026-11-28): 1235 entries, fields id, name, default,
premium, cdnType, country, subtitle, host, internalServer, udpSupport,
uuid, protocol (VLESS/VMESS/SHADOWSOCKS/TROJAN; absent on the 13 official
servers), transport/security (top level on some), wsHost, wsPath,
alterId, paths[] (id, label, transport, security, ports[], tlsFingerprint,
tlsAlpn, sni, wsHost, wsPath, xhttpMode, encryption, ...).
Configs (live): 63 profiles, fields id, name, description, cdnType,
cdnTypeDefault, port, transport (WS/XHTTP/httpupgrade/V2K/socketcustom),
security (tls/none/reality), host, sni, path, hostHeader, recommended,
protocol, encryption, flow, tlsAlpn, tlsFingerprint, payload (18 configs
carry a [crlf]/[split] payload template), MUX, v2k* tuning fields,
socketCustom* fields, fragment* fields, xhttp* fields.

.v2k file format (V2kFileFormat.kt, V2kImporter.kt):
  "V2K1|<flags hex, 2 digits>|<payload>"
  flags bit 0 (FLAG_ENCRYPTED = 1): payload is the CryptoHelper envelope
  above (AES-256-GCM, same key); otherwise payload is plain JSON.
  JSON: {"name", "description", "createdAt", "version", "xray": "<Xray
  config JSON as a string>", "manual": "<ManualConfig JSON string,
  optional>", "meta": {"appVersion", "author", "requiredServerId",
  "requiredServerName", "requiredCdnType", "activeTransport",
  "activeSecurity", "activeXhttpMode", "activePort", "serverHostValue",
  "sniValue", "hostHeaderValue", "hostAlias" (default "[host]"),
  "aliasedFields": [...], "originalAliasValue": ""}}
  Imported in-app with ACTION_OPEN_DOCUMENT ("*/*", file must end in
  .v2k); there is NO intent-filter for .v2k in the manifest.
  No real exported .v2k sample was available: the decoder is verified by
  self round-trip (serialize -> parse, plain and encrypted).

Xray JSON import (XrayJsonImporter.kt): plain Xray-core JSON config text
(full config with inbounds/outbounds, or a single inbound/outbound
object); the app normalizes it (protocol names, ports, JSON-like fields)
and keeps the detected protocol + source type. The decoder parses the
JSON and extracts the outbound(s) in clear text.

Text links (VlessLinkParser.kt, supportedSchemes):
  vless://, vmess://, trojan://, ss:// -- standard forms, parsed from
  pasted/clipboard text (first supported link wins). No app-owned scheme
  (there is no v2k:// scheme). vmess:// accepts base64 JSON and a
  URI-like uuid@host:port form; ss:// accepts both the whole-payload
  base64 form and the base64(method:password)@host:port form, plus a
  plugin= query parameter. Query parameters understood: type/transport,
  security, sni, host, path, encryption, flow, serviceName, headerType,
  plus the app's socketcustom (mode, customPayload, strictHandshake,
  payloadDelayMs, splitDelayMs, responseTimeoutMs, throughputUpBps,
  throughputDownBps, throughputBurstBytes) and v2k (mode, paddingProfile,
  pullConcurrency, downloadChunkBytes, uploadChunkBytes, pushFlushDelayMs,
  keepAliveMs, sessionIdleTimeoutMs, listenMode, pollRequestClassBytes,
  pollResponseFrameBytes, authMode, authId, psk, aeadEnabled, aeadCipher)
  parameters.

Usage:
  python3 v2ray_injector.py                  fetch live catalog, print stats
  python3 v2ray_injector.py catalog [out]    fetch live catalog, write JSON
  python3 v2ray_injector.py decrypt <iv.ct>  decrypt one envelope string
  python3 v2ray_injector.py v2k <file.v2k>   decode a .v2k file
  python3 v2ray_injector.py v2k-encode <config.json> <out.v2k> [--encrypt]
                                             build a .v2k file (round-trip test)
  python3 v2ray_injector.py link <url>       decode a vmess/vless/trojan/ss link
  python3 v2ray_injector.py xray <file.json> import an Xray JSON config

Requires: Python 3 stdlib + `cryptography` (AESGCM), with a PyCryptodome
fallback. No other dependencies.
"""

import base64
import binascii
import json
import os
import re
import sys
import time
import urllib.parse
import urllib.request

# ---------------------------------------------------------------- crypto

CATALOG_KEY = bytes.fromhex(
    "4a7b9c2d3e5f6a8b1c0d2e4f6789abcd"
    "0123456789abcdef0123456789abcdef"
)
WORKER_URL = "https://xraytunnel-config.admin6795.workers.dev/api/config"
API_KEY = "a112be46639d73d581813ecd2a382c6b"
USER_AGENT = "XrayTunnel/1.0"

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    def _gcm_decrypt(key, iv, ct):
        return AESGCM(key).decrypt(iv, ct, None)

    def _gcm_encrypt(key, iv, pt):
        return AESGCM(key).encrypt(iv, pt, None)

except ImportError:  # PyCryptodome fallback
    from Crypto.Cipher import AES

    def _gcm_decrypt(key, iv, ct):
        cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
        return cipher.decrypt_and_verify(ct[:-16], ct[-16:])

    def _gcm_encrypt(key, iv, pt):
        cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
        ct, tag = cipher.encrypt_and_digest(pt)
        return ct + tag


def decrypt_envelope(encrypted):
    """CryptoHelper.decrypt: 'base64(iv).base64(ciphertext+tag)' -> str."""
    if not isinstance(encrypted, str) or "." not in encrypted:
        raise ValueError("Invalid encrypted format. Expected: iv.ciphertext")
    iv_b64, ct_b64 = encrypted.split(".", 1)
    iv = base64.b64decode(iv_b64)
    ct = base64.b64decode(ct_b64)
    if len(iv) != 12:
        raise ValueError("Invalid IV length: %d" % len(iv))
    return _gcm_decrypt(CATALOG_KEY, iv, ct).decode("utf-8")


def decrypt_envelope_or_none(encrypted):
    if not encrypted or not isinstance(encrypted, str):
        return None
    try:
        return decrypt_envelope(encrypted)
    except Exception:
        return None


def encrypt_envelope(plaintext):
    """CryptoHelper.encrypt: random 12 B IV, AES-256-GCM, 'iv.ct' base64."""
    if isinstance(plaintext, str):
        plaintext = plaintext.encode("utf-8")
    iv = os.urandom(12)
    ct = _gcm_encrypt(CATALOG_KEY, iv, plaintext)
    return base64.b64encode(iv).decode() + "." + base64.b64encode(ct).decode()


# ---------------------------------------------------------------- catalog

def fetch_catalog_raw(retries=3, timeout=60):
    """Replicates SecureConfigFetcher.fetchFromWorker exactly: GET, the
    three headers, 3 attempts with (attempt+1)*1000 ms delay. The app
    sets 10 s connect/read timeouts; this script defaults to 60 s
    because the 815 KB response takes ~23 s through this VM's proxy --
    the request itself (method, URL, headers, no body) is identical."""
    headers = {
        "Accept": "application/json",
        "User-Agent": USER_AGENT,
        "X-API-KEY": API_KEY,
    }
    last_exc = None
    for attempt in range(retries):
        try:
            req = urllib.request.Request(WORKER_URL, headers=headers, method="GET")
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                if resp.status != 200:
                    raise RuntimeError("HTTP %d" % resp.status)
                return resp.read().decode("utf-8")
        except Exception as exc:  # noqa: BLE001 - retry loop mirrors the app
            last_exc = exc
            if attempt < retries - 1:
                time.sleep((attempt + 1) * 1.0)
    raise RuntimeError("Failed to fetch after %d retries: %s" % (retries, last_exc))


def decode_catalog_response(raw):
    """Worker-response bytes/str -> decrypted catalog dict (no fetch).

    Bridge entry point used by server_catalog_decoder.run(): the broker
    downloads the live response and hands the raw bytes here. Result has
    no download APIs, only the decrypted catalog data (plus
    version/release metadata). Raises ValueError on a malformed
    response or an envelope that fails to decrypt.
    """
    if isinstance(raw, (bytes, bytearray)):
        raw = raw.decode("utf-8")
    try:
        resp = json.loads(raw)
    except ValueError as exc:
        raise ValueError("Invalid catalog response JSON") from exc
    if not isinstance(resp, dict) or "servers" not in resp or "configs" not in resp:
        raise ValueError("Catalog response has no servers/configs envelopes")
    try:
        servers = json.loads(decrypt_envelope(resp["servers"]))
        configs = json.loads(decrypt_envelope(resp["configs"]))
    except Exception as exc:
        raise ValueError("Catalog envelope failed to decrypt") from exc
    return {
        "version": resp.get("version"),
        "catalogSource": resp.get("catalogSource"),
        "catalogReleaseId": resp.get("catalogReleaseId"),
        "catalogSnapshotId": resp.get("catalogSnapshotId"),
        "timestamp": resp.get("timestamp"),
        "servers": servers["servers"],
        "configs": configs["configs"],
    }


def run(data):
    """Bridge contract: raw worker-response bytes -> catalog JSON string."""
    if not isinstance(data, (bytes, bytearray)) or not data:
        raise ValueError("empty catalog response")
    if len(data) > 8 * 1024 * 1024:
        raise ValueError("catalog response exceeds 8 MiB")
    catalog = decode_catalog_response(data)
    if not catalog.get("servers"):
        raise ValueError("catalog has no servers")
    return json.dumps(catalog, ensure_ascii=False, indent=2) + "\n"


def fetch_catalog():
    """Fetch + decrypt the live catalog. Result has no download APIs,
    only the decrypted catalog data (plus version/release metadata)."""
    return decode_catalog_response(fetch_catalog_raw())


_IP_RE = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$|^[0-9a-fA-F:]+:[0-9a-fA-F:]+$")


def _is_ip(value):
    if not isinstance(value, str) or not value:
        return False
    if _IP_RE.match(value):
        return True
    try:
        import ipaddress
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _scrub_ips(value):
    """Recursively replace any IPv4 literal embedded in any string value
    (e.g. an IP hidden inside a wsPath like '/1.2.3.4:443') with the
    placeholder REDACTED. Field-level redaction above only catches whole
    values that ARE an IP; this catches IPs nested inside other strings."""
    if isinstance(value, str):
        return _IP_EMBEDDED_RE.sub("REDACTED", value)
    if isinstance(value, list):
        return [_scrub_ips(v) for v in value]
    if isinstance(value, dict):
        return {k: _scrub_ips(v) for k, v in value.items()}
    return value


_IP_EMBEDDED_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


def redact_catalog(catalog):
    """Redacted copy: IPs and passwords/credentials removed. Hostnames are
    kept (they are not IPs). The complete copy is catalogo_completo.json
    and must never go in the ZIP."""
    def redact_server(srv):
        out = dict(srv)
        out["uuid"] = ""  # credential (UUID / SS password / Trojan password)
        for key in ("host", "wsHost"):
            if _is_ip(out.get(key)):
                out[key] = ""
        for path in out.get("paths", []) or []:
            if isinstance(path, dict):
                for key in ("wsHost", "sni"):
                    if _is_ip(path.get(key)):
                        path[key] = ""
        return out

    def redact_config(cfg):
        out = dict(cfg)
        for key in ("host", "sni", "wsHost", "customHost", "v2kHost", "v2kPsk"):
            if key == "v2kPsk":
                out[key] = ""
            elif _is_ip(out.get(key)):
                out[key] = ""
        return out

    red = dict(catalog)
    red["servers"] = [redact_server(s) for s in catalog.get("servers", [])]
    red["configs"] = [redact_config(c) for c in catalog.get("configs", [])]
    red["redaction_note"] = (
        "Copia redactada: uuid/contrasenas vaciados y hosts que son IPs "
        "literales vaciados. Los hostnames se conservan (no son IPs). "
        "La copia completa con credenciales intactas es "
        "catalogo_completo.json y NO va en el ZIP."
    )
    # Second pass: scrub any IPv4 literal embedded inside any string
    # (e.g. wsPath '/1.2.3.4:443'), which field-level checks miss.
    return _scrub_ips(red)


# ---------------------------------------------------------------- .v2k

V2K_MAGIC = "V2K1"
FLAG_ENCRYPTED = 1


def parse_v2k(content):
    """V2kFileFormat.parse: 'V2K1|<flags hex>|<payload>' -> dict with the
    parsed JSON (xray/manual parsed as JSON when possible)."""
    if isinstance(content, bytes):
        content = content.decode("utf-8")
    text = content.strip().lstrip("\ufeff").strip()
    if not text.startswith(V2K_MAGIC + "|"):
        raise ValueError("Invalid V2K file format")
    parts = text.split("|", 2)
    if len(parts) != 3:
        raise ValueError("Invalid V2K structure")
    try:
        flags = int(parts[1], 16)
    except ValueError:
        raise ValueError("Invalid flags")
    encrypted = bool(flags & FLAG_ENCRYPTED)
    payload = parts[2]
    if encrypted:
        payload = decrypt_envelope_or_none(payload)
        if payload is None:
            raise ValueError("Failed to decrypt V2K file")
    try:
        doc = json.loads(payload)
    except json.JSONDecodeError as exc:
        raise ValueError("Failed to parse V2K JSON: %s" % exc)
    meta = doc.get("meta") or {}
    result = {
        "name": doc.get("name", "Imported Config"),
        "description": doc.get("description", ""),
        "createdAt": doc.get("createdAt", ""),
        "version": doc.get("version", 1),
        "encrypted": encrypted,
        "meta": meta,
        "xray": doc.get("xray", ""),
        "manual": doc.get("manual"),
    }
    for key in ("xray", "manual"):
        raw = result[key]
        if isinstance(raw, str) and raw.strip().startswith("{"):
            try:
                result[key + "_json"] = json.loads(raw)
            except json.JSONDecodeError:
                pass
    return result


def serialize_v2k(config, encrypt=False):
    """V2kFileFormat.serialize: dict -> 'V2K1|<flags>|<payload>'."""
    meta = dict(config.get("meta") or {})
    if not meta.get("hostAlias"):
        meta["hostAlias"] = "[host]"
    doc = {
        "name": config.get("name", "Imported Config"),
        "description": config.get("description", ""),
        "createdAt": config.get("createdAt", ""),
        "version": config.get("version", 1),
        "xray": config.get("xray", ""),
        "meta": meta,
    }
    if config.get("manual"):
        doc["manual"] = config["manual"]
    payload = json.dumps(doc, ensure_ascii=False)
    flags = "%02x" % (FLAG_ENCRYPTED if encrypt else 0)
    if encrypt:
        payload = encrypt_envelope(payload)
    return "%s|%s|%s" % (V2K_MAGIC, flags, payload)


def decode_v2k_file(path):
    with open(path, "r", encoding="utf-8-sig") as f:
        return parse_v2k(f.read())


# ---------------------------------------------------------------- Xray JSON

def import_xray_json(content):
    """XrayJsonImporter.importFromString: parse an Xray-core JSON config
    (full config or a single inbound/outbound object) and extract the
    outbound(s) in clear text."""
    if isinstance(content, bytes):
        content = content.decode("utf-8")
    doc = json.loads(content)
    if not isinstance(doc, dict):
        raise ValueError("Xray JSON must be an object")
    outbounds = []
    if "outbounds" in doc:
        source_type = "full-config"
        outbounds = doc.get("outbounds") or []
    elif doc.get("protocol") and ("settings" in doc or "streamSettings" in doc):
        source_type = "outbound-object"
        outbounds = [doc]
    elif "inbounds" in doc and "outbounds" not in doc:
        source_type = "inbound-object"
        outbounds = []
    else:
        source_type = "unknown-json"
    parsed = []
    for ob in outbounds:
        if not isinstance(ob, dict):
            continue
        settings = ob.get("settings") or {}
        servers = settings.get("servers") or settings.get("vnext") or []
        entry = {
            "tag": ob.get("tag", ""),
            "protocol": (ob.get("protocol") or "").lower(),
            "streamSettings": ob.get("streamSettings") or {},
            "settings": settings,
        }
        if servers and isinstance(servers, list) and isinstance(servers[0], dict):
            srv = servers[0]
            entry["address"] = srv.get("address", "")
            entry["port"] = srv.get("port")
            users = srv.get("users") or []
            if users and isinstance(users[0], dict):
                entry["uuid"] = users[0].get("id", "")
                entry["encryption"] = users[0].get("encryption", "")
                entry["flow"] = users[0].get("flow", "")
            entry["password"] = srv.get("password", "")
            entry["method"] = srv.get("method", "")
        parsed.append(entry)
    return {
        "sourceType": source_type,
        "normalizedJson": doc,
        "detectedProtocol": parsed[0]["protocol"] if parsed else "",
        "outbounds": parsed,
    }


# ---------------------------------------------------------------- text links

def _b64decode_utf8(raw):
    """decodeBase64ToUtf8: base64 (standard or urlsafe, padding optional)
    -> str, or None."""
    if raw is None:
        return None
    s = raw.strip()
    if not s:
        return None
    s = s.replace("-", "+").replace("_", "/")
    s += "=" * (-len(s) % 4)
    try:
        return base64.b64decode(s).decode("utf-8")
    except (binascii.Error, UnicodeDecodeError, ValueError):
        return None


def _parse_query(raw_query):
    out = {}
    for key, values in urllib.parse.parse_qs(raw_query, keep_blank_values=True).items():
        out[key.lower()] = values[0] if values else ""
    return out


def _query_value(query, *keys):
    for key in keys:
        if key in query:
            return query[key]
    return None


def _to_bool(value):
    if value is None:
        return None
    return str(value).strip().lower() in ("1", "true", "yes", "on")


def _to_int(value):
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return None


def _socketcustom_params(transport, query):
    if (transport or "").lower() != "socketcustom":
        return None
    return {
        "mode": _query_value(query, "mode"),
        "customPayload": _to_bool(_query_value(query, "custompayload", "custom_payload")),
        "strictHandshake": _to_bool(_query_value(query, "stricthandshake", "strict_handshake")),
        "payloadDelayMs": _to_int(_query_value(query, "payloaddelayms", "payload_delay_ms")),
        "splitDelayMs": _to_int(_query_value(query, "splitdelayms", "split_delay_ms")),
        "responseTimeoutMs": _to_int(_query_value(query, "responsetimeoutms", "response_timeout_ms")),
        "throughputUpBps": _to_int(_query_value(query, "throughputupbps", "throughput_up_bps")),
        "throughputDownBps": _to_int(_query_value(query, "throughputdownbps", "throughput_down_bps")),
        "throughputBurstBytes": _to_int(_query_value(query, "throughputburstbytes", "throughput_burst_bytes")),
    }


def _v2k_params(query):
    keys = ("mode", "paddingprofile", "pullconcurrency", "downloadchunkbytes",
            "uploadchunkbytes", "pushflushdelayms", "keepalivems",
            "sessionidletimeoutms", "listenmode", "pollrequestclassbytes",
            "pollresponseframebytes", "authmode", "authid", "psk",
            "aeadenabled", "aeadcipher")
    found = {}
    for key in keys:
        value = _query_value(query, key, "v2k" + key)
        if value is not None:
            found[key] = value
    return found or None


def _common_link_fields(protocol, uuid, address, port, query, remark):
    transport = _query_value(query, "type", "transport") or ""
    return {
        "protocol": protocol,
        "uuid": uuid,
        "address": address,
        "port": port,
        "transport": transport,
        "security": _query_value(query, "security") or "",
        "encryption": _query_value(query, "encryption") or "",
        "flow": _query_value(query, "flow") or "",
        "sni": _query_value(query, "sni") or "",
        "host": _query_value(query, "host") or "",
        "path": _query_value(query, "path") or "",
        "serviceName": _query_value(query, "servicename") or "",
        "headerType": _query_value(query, "headertype") or "",
        "remark": remark or "",
        "socketCustom": _socketcustom_params(transport, query),
        "v2k": _v2k_params(query),
    }


def _split_hostport(authority):
    """'host:port' / '[v6]:port' -> (host, port or None)."""
    if authority.startswith("["):
        end = authority.find("]")
        host = authority[1:end] if end > 0 else authority
        rest = authority[end + 1:]
        port = _to_int(rest[1:]) if rest.startswith(":") else None
        return host, port
    if ":" in authority:
        host, _, port = authority.rpartition(":")
        return host, _to_int(port)
    return authority, None


def parse_vless(link):
    uri = urllib.parse.urlparse(link)
    uuid = urllib.parse.unquote(uri.username or "")
    host, port = _split_hostport(uri.netloc.rsplit("@", 1)[-1])
    query = _parse_query(uri.query)
    remark = urllib.parse.unquote(uri.fragment or "")
    return _common_link_fields("VLESS", uuid, host, port, query, remark)


def parse_trojan(link):
    uri = urllib.parse.urlparse(link)
    password = urllib.parse.unquote(uri.username or "")
    host, port = _split_hostport(uri.netloc.rsplit("@", 1)[-1])
    query = _parse_query(uri.query)
    remark = urllib.parse.unquote(uri.fragment or "")
    out = _common_link_fields("TROJAN", password, host, port, query, remark)
    out["password"] = password
    return out


def _vmess_json(obj, remark):
    return {
        "protocol": "VMESS",
        "uuid": obj.get("id", ""),
        "address": obj.get("add", ""),
        "port": _to_int(obj.get("port")),
        "transport": obj.get("net", ""),
        "security": obj.get("tls", ""),
        "encryption": "",
        "flow": "",
        "sni": obj.get("sni", "") or obj.get("host", ""),
        "host": obj.get("host", ""),
        "path": obj.get("path", ""),
        "serviceName": "",
        "headerType": obj.get("type", ""),
        "remark": remark or obj.get("ps", ""),
        "alterId": _to_int(obj.get("aid")),
        "vmess": obj,
        "socketCustom": None,
        "v2k": None,
    }


def parse_vmess(link):
    body = link[len("vmess://"):] if link.lower().startswith("vmess://") else link
    body = body.strip()
    main, _, fragment = body.partition("#")
    remark = urllib.parse.unquote(fragment) if fragment else None
    decoded = _b64decode_utf8(main.strip())
    if decoded is not None:
        text = decoded.strip()
        if text.startswith("{"):
            return _vmess_json(json.loads(text), remark)
    # URI-like fallback (parseVmessUriLike): uuid@host:port?query
    uri = urllib.parse.urlparse("vmess://" + body)
    uuid = urllib.parse.unquote(uri.username or "")
    host, port = _split_hostport(uri.netloc.rsplit("@", 1)[-1])
    query = _parse_query(uri.query)
    return _common_link_fields("VMESS", uuid, host, port, query, remark or "")


def parse_shadowsocks(link):
    body = link[len("ss://"):] if link.lower().startswith("ss://") else link
    body = body.strip()
    main, _, fragment = body.partition("#")
    remark = urllib.parse.unquote(fragment) if fragment else ""
    main, _, query_s = main.partition("?")
    query = _parse_query(query_s)
    if "@" not in main:
        decoded = _b64decode_utf8(main)
        if decoded is None:
            raise ValueError("Invalid Shadowsocks payload")
        main = decoded.strip()
        main, _, query_s2 = main.partition("?")
        if query_s2:
            query = _parse_query(query_s2)
    cred_b64, _, hostport = main.rpartition("@")
    if not cred_b64 or not hostport:
        raise ValueError("Invalid Shadowsocks endpoint")
    cred = urllib.parse.unquote(cred_b64)
    if ":" not in cred:
        cred = _b64decode_utf8(cred_b64) or ""
        cred = urllib.parse.unquote(cred)
    if ":" not in cred:
        raise ValueError("Invalid Shadowsocks credential")
    method, _, password = cred.partition(":")
    host, port = _split_hostport(hostport)
    if not port:
        raise ValueError("Missing Shadowsocks port")
    out = {
        "protocol": "SHADOWSOCKS",
        "uuid": password,
        "password": password,
        "method": method.strip(),
        "address": host,
        "port": port,
        "transport": "TCP",
        "security": "none",
        "encryption": method.strip(),
        "flow": "",
        "sni": "",
        "host": "",
        "path": "",
        "serviceName": "",
        "headerType": "",
        "remark": remark,
        "plugin": query.get("plugin", ""),
        "socketCustom": None,
        "v2k": None,
    }
    return out


SUPPORTED_SCHEMES = ("vless://", "vmess://", "trojan://", "ss://")


def extract_first_supported_link(text):
    """extractFirstSupportedLink: first occurrence of a supported scheme
    in pasted text (case-insensitive)."""
    lowered = text.lower()
    best = None
    for scheme in SUPPORTED_SCHEMES:
        idx = lowered.find(scheme)
        if idx >= 0 and (best is None or idx < best[0]):
            best = (idx, scheme)
    if best is None:
        raise ValueError("Unsupported scheme")
    start = best[0]
    end = len(text)
    for sep in (" ", "\n", "\r", "\t"):
        pos = text.find(sep, start)
        if pos >= 0:
            end = min(end, pos)
    return text[start:end].strip()


def parse_link(text):
    link = extract_first_supported_link(text.strip())
    lowered = link.lower()
    if lowered.startswith("vless://"):
        return parse_vless(link)
    if lowered.startswith("vmess://"):
        return parse_vmess(link)
    if lowered.startswith("trojan://"):
        return parse_trojan(link)
    if lowered.startswith("ss://"):
        return parse_shadowsocks(link)
    raise ValueError("Unsupported scheme")


# ---------------------------------------------------------------- CLI

def _print_json(obj):
    print(json.dumps(obj, indent=1, ensure_ascii=False))


def main(argv):
    if len(argv) < 2:
        catalog = fetch_catalog()
        print("V2Ray Injector catalog version %s (%s / %s)"
              % (catalog["version"], catalog["catalogReleaseId"],
                 catalog["catalogSnapshotId"]))
        print("servers: %d  configs: %d"
              % (len(catalog["servers"]), len(catalog["configs"])))
        return 0

    cmd = argv[1]
    if cmd == "catalog":
        catalog = fetch_catalog()
        out = argv[2] if len(argv) > 2 else "catalogo-completo.json"
        with open(out, "w", encoding="utf-8") as f:
            json.dump(catalog, f, indent=1, ensure_ascii=False)
        print("wrote %s (%d servers, %d configs)"
              % (out, len(catalog["servers"]), len(catalog["configs"])))
        return 0
    if cmd == "decrypt":
        _print_json({"plaintext": decrypt_envelope(argv[2])})
        return 0
    if cmd == "v2k":
        _print_json(decode_v2k_file(argv[2]))
        return 0
    if cmd == "v2k-encode":
        with open(argv[2], "r", encoding="utf-8") as f:
            config = json.load(f)
        encrypt = "--encrypt" in argv[3:]
        out = argv[3] if len(argv) > 3 and not argv[3].startswith("--") else None
        text = serialize_v2k(config, encrypt=encrypt)
        if out:
            with open(out, "w", encoding="utf-8") as f:
                f.write(text)
            print("wrote %s (encrypted=%s)" % (out, encrypt))
        else:
            print(text)
        return 0
    if cmd == "link":
        _print_json(parse_link(argv[2]))
        return 0
    if cmd == "xray":
        with open(argv[2], "r", encoding="utf-8") as f:
            _print_json(import_xray_json(f.read()))
        return 0
    print("usage: v2ray_injector.py [catalog [out]|decrypt <iv.ct>|"
          "v2k <file>|v2k-encode <config.json> <out> [--encrypt]|"
          "link <url>|xray <file.json>]")
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))

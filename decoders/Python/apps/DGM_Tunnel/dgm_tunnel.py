#!/usr/bin/env python3
"""DGM Tunnel (com.dgmtunnel.app) 15.11.2026 (versionCode 17): catalog + file decoder.

DGM Tunnel is NOT a StrongTeam/VLX-style app, even though it ships the same
stock libgojni.so (AndroidLibXrayLite, Go 1.27.1, SHA-256
1605ddb3d2a6331b7bc1d3cff4bf20829d4a0f41e4c64d502528ca8d0bede9da):
that library is only the Xray core, it holds no catalog keys (the VLX
format passwords are absent from it: 0 occurrences) and no catalog URL.
There is no Argon2id / AES-GCM envelope anywhere in this app and nothing
in the live catalog is encrypted: the "free server catalog" is a plain
public subscription list fetched over HTTPS and parsed line by line.

    GET https://raw.githubusercontent.com/barry-far/V2ray-config/main/All_Configs_Sub.txt
    User-Agent: DGMTunnel/1.5

Exact request as the app sends it (FreeServerCatalog.fetch): plain GET, no
body, no auth, no cookies, connect/read timeout 15 s each, redirects NOT
followed, 4 MiB size cap (readConfigText). The body is a UTF-8 subscription
text (profile-title / subscription-userinfo comment lines, then one VPN
link per line: vless://, ss://, trojan://, vmess://, hysteria2://, hy2://,
ssr://). The app parses it with ConfigImporter.parse(text, 500) -- at most
the first 500 profiles that parse -- then FreeServerCatalog drops SSH
profiles and proxy (inject) profiles, dedupes by protocol:server:port:uuid,
takes the first 40, renames them public-0..public-39 and truncates each
name to 90 characters. This script replicates that pipeline exactly
(ConfigImporter.kt + FreeServerCatalog.kt, decompiled with jadx 1.5.3),
including the app's strict per-link rules, so the 40 profiles it outputs
are the 40 the app shows:

- vless/trojan/ssh (uriConfig): transport must be tcp/raw/ws, security
  tls/none/"", no VLESS flow (XTLS rejected), headerType none-or-blank,
  encryption none-or-blank. So reality, xhttp, grpc and flow links are
  REJECTED by the app. hysteria2://, hy2:// and ssr:// are not supported
  at all ("Lien non pris en charge"); a link with raw non-ASCII in it
  fails earlier at new URI(...) (URISyntaxException).
- vmess://: Base64 JSON, net tcp/ws/raw, tls ""/none/tls, aid must be 0,
  type ""/none, security (scy) auto/aes-128-gcm/chacha20-poly1305/none/zero.
- ss://: method:password@host:port (either part Base64), no plugin=,
  method must be aes-128-gcm / aes-256-gcm / chacha20-ietf-poly1305 /
  2022-blake3-aes-128-gcm / 2022-blake3-aes-256-gcm /
  2022-blake3-chacha20-poly1305.
- darktunnel:// / dgmtunnel://: Base64 JSON, either a plain TunnelConfig
  JSON ({"server": ...}) or the DarkTunnel node form
  (vlessTunnelConfig / trojanTunnelConfig / vmessTunnelConfig, each with
  v2rayConfig + injectConfig).
- JSON input: a Profile JSON ({"config": ...}), a TunnelConfig JSON
  ({"server": ...}), a vmess JSON ({"add": ..., "id": ...}), or a JSON
  array of any of those. A whole-file Base64 blob is unwrapped first.
  JSON with "ciphertext"/"enc" is rejected by the app (EYJ chiffre).

Every parsed profile is then normalised (NetworkEndpoint.parse: host/port
split, IPv6 brackets, contradictory-port rejection) and validated
(XrayConfig.validate, forImport=true): server required, port 1-65535,
uuid/password required unless the protocol is "simple", vmessSecurity in
its set, TLS peer pin must be 64 hex chars, SSH needs a username.
Entries that fail any step are skipped and reported as
"Entree N : <message>", exactly like the app's ImportResult.errors.

LIVE STATUS (2026-11-28, fetch at ~02:00 PST): the feed answers HTTP 200,
2,122,468 bytes, 8,880 lines / 8,873 links. Scanning in order, the first
500 profiles that parse are reached after 557 lines (57 rejected):
all 500 are Shadowsocks -- the feed is grouped by scheme and the first
557 lines hold 503 ss://, 45 hysteria2://, 5 hy2:// and 4 vless:// (all
4 vless rejected: 2 reality, 2 xhttp). After the SSH/proxy filter (no-op
here) and the protocol:server:port:uuid dedupe, 171 unique profiles
remain; the catalog is the first 40 of those, all Shadowsocks
(2022-blake3-chacha20-poly1305 x24, 2022-blake3-aes-256-gcm x13,
aes-256-gcm x2, 2022-blake3-aes-128-gcm x1), ports 443 x23, 8388 x2 and
assorted high ports. There are no payloads and no networks in this
catalog: it is 40 server profiles, not a Servers/Networks catalog.
The feed is a rolling third-party list, so the 40 change as its head
moves; the JSON records fetched_at, feed_lines and the rejection counts
for the snapshot. Rejected counts by reason for this snapshot: 26
unsupported scheme (hysteria2/hy2/ssr), 24 raw non-ASCII in the link
(Java URI), 2 security=reality, 2 transport=xhttp, 2 bad Base64/UTF-8
in ss://, 1 Shadowsocks method not supported.

NOTE on ConfigImporter.parse dedupe: jadx shows a loop over the profiles
already collected comparing full TunnelConfig equality, followed by an
unconditional add -- the decompilation drops the guard, so it is ambiguous
whether the app dedupes exact-duplicate configs while collecting the 500
(4 exact duplicates occur in the first 500 of this snapshot). It does not
matter for the delivered catalog: the catalog dedupe by
protocol:server:port:uuid removes those same 4, and the first 40 are
byte-identical under both readings (verified). This script implements the
dedupe (the loop's evident intent).

FILE DECODER (same ConfigImporter): the manifest declares VIEW intents
for the schemes darktunnel, dgmtunnel, vless, vmess, trojan (plus ss/ssh
in code) and mime types application/json and application/octet-stream --
no dedicated file extension, no .sks. Any text/JSON file holding links,
a JSON profile/array, or a Base64 subscription parses with parse().
This script is also that file decoder: give it a file (or --stdin) and it
outputs the parsed profiles and the per-entry errors. A DGMTUNNEL_SHARE
v2 sealed share (dgmtunnel://share/<base64url> or the raw envelope JSON)
opens with --share-password: PBKDF2-HMAC-SHA256, 600,000 iterations,
salt 16 B, AES-256-GCM, IV 12 B, AAD = the envelope header fields joined
as "key=value" lines (format, version, id, createdAt, expiresAt, locked,
passwordProtected, iterations, salt, iv, then v2 deviceId, hourStart,
hourEnd, message); the plaintext is a TunnelConfig JSON. The share is
checked for expiry against the local clock and its deviceId binding is
reported (not enforced here: there is no device id in this environment).
The sample share seen in the batch (id 9bcf46a7-...) is EXPIRED
(expiresAt 2026-11-27 11:17 PST) and its password is unknown, so it
cannot be opened; no password is ever brute-forced by this script.

The result JSON contains only catalog/profile data, never the feed URL
and never any download API. The CloudShares backend
(https://xhat-app.preview.emergentagent.com, /api/shares) is only the
share-link service, not a catalog source, and is not used here.
No account credentials of any kind live in this script.
"""
from __future__ import annotations

import argparse
import base64
import binascii
import getpass
import hashlib
import json
import math
import re
import sys
import time
from http.client import HTTPException
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import unquote, urlsplit, urlunsplit

MAX_BYTES = 4 * 1024 * 1024
MAX_DEPTH = 64
MAX_NODES = 1_000_000

FEED_URL = "https://raw.githubusercontent.com/barry-far/V2ray-config/main/All_Configs_Sub.txt"
SOURCE_NAME = "barry-far / V2ray-Config (GitHub)"
USER_AGENT = "DGMTunnel/1.5"
APP_PACKAGE = "com.dgmtunnel.app"
APP_VERSION_NAME = "15.11.2026"
APP_VERSION_CODE = 17
PARSE_LIMIT = 500
CATALOG_TAKE = 40

SCHEMES = {"vless", "vmess", "trojan", "ss", "ssh", "darktunnel", "dgmtunnel"}
DEFAULT_PORT = {"VLESS": 443, "VMESS": 443, "TROJAN": 443,
                "SHADOWSOCKS": 8388, "SSH": 22}
SIMPLE_PROTOCOLS = {"HTTP_PROXY", "SOCKS5", "PAYLOAD", "SNI_HOST", "DNS_ONLY"}
SECRET_LABEL = {"VLESS": "UUID", "VMESS": "UUID", "TROJAN": "Password",
                "SHADOWSOCKS": "Password", "SSH": "Password"}
VMESS_SECURITY = {"auto", "aes-128-gcm", "chacha20-poly1305", "none", "zero"}
SS_METHODS = {"aes-128-gcm", "aes-256-gcm", "chacha20-ietf-poly1305",
              "2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm",
              "2022-blake3-chacha20-poly1305"}
SHARE_FORMAT = "DGMTUNNEL_SHARE"
SHARE_ITERATIONS = 600000


class DecodeError(ValueError):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


# ---------------------------------------------------------------- helpers
def _config(name, protocol, server, port, uuid, websocket=False, ws_path="/",
            ws_host="", tls=True, sni="", mux=False, mux_conc="8", proxy=False,
            proxy_host="", proxy_port="", payload="", ss_method="aes-256-gcm",
            ssh_user="", ssh_fp="", vmess_sec="auto", allow_insecure=None,
            tls_fp="", tls_alpn="", tls_pin="", share_policy=None):
    """One TunnelConfig, with the app's synthetic-constructor defaults."""
    return {"name": name, "protocol": protocol, "server": server,
            "port": str(port), "uuid": uuid, "websocket": websocket,
            "wsPath": ws_path, "wsHost": ws_host, "tls": tls, "sni": sni,
            "mux": mux, "muxConcurrency": mux_conc, "proxy": proxy,
            "proxyHost": proxy_host, "proxyPort": proxy_port,
            "payload": payload, "ssMethod": ss_method, "sshUser": ssh_user,
            "sshFingerprint": ssh_fp, "vmessSecurity": vmess_sec,
            "allowInsecure": allow_insecure, "tlsFingerprint": tls_fp,
            "tlsAlpn": tls_alpn, "tlsPeerPin": tls_pin,
            "sharePolicy": share_policy}


def _profile(config, alt=None, profile_id="import"):
    return {"id": profile_id, "name": config["name"], "config": config,
            "alt": alt}


def _decode_url(value: str) -> str:
    """ConfigImporter.decode: URLDecoder.decode(value with '+' kept, UTF-8)."""
    return unquote(value.replace("+", "%2B"), encoding="utf-8", errors="strict")


def _b64decode_text(value: str) -> str:
    """ConfigImporter.decodeBase64: strip whitespace, URL-safe -> standard."""
    s = re.sub(r"\s+", "", value).replace("-", "+").replace("_", "/")
    s += "=" * (-len(s) % 4)
    return base64.b64decode(s, validate=False).decode("utf-8")


def _b64decode_bytes(value: str) -> bytes:
    s = re.sub(r"\s+", "", value).replace("-", "+").replace("_", "/")
    s += "=" * (-len(s) % 4)
    return base64.b64decode(s, validate=False)


def _parse_bool(value):
    """ConfigImporter.parseBoolean: true/false/1/0/yes/no/on/off, else error."""
    if value is None:
        return None
    if isinstance(value, bool):
        return value
    s = str(value).strip().lower()
    if s in ("", "null"):
        return None
    if s in ("1", "true", "yes", "on"):
        return True
    if s in ("0", "false", "no", "off"):
        return False
    raise DecodeError("INVALID_BOOL",
                      "Valeur TLS insecure invalide (true/false ou 1/0 attendus).")


def _parse_alpn(value) -> str:
    if value is None:
        return ""
    if isinstance(value, list):
        parts = [str(x).strip() for x in value]
    else:
        parts = [p.strip() for p in re.split(r"[,;]", str(value))]
    return ",".join(p for p in parts if p)


def _port_or_error(s) -> int:
    try:
        v = int(str(s).strip())
    except (ValueError, AttributeError):
        raise DecodeError("INVALID_PORT", f"Port invalide : {s}")
    if not 1 <= v < 65536:
        raise DecodeError("INVALID_PORT", f"Port invalide : {s}")
    return v


def _parse_endpoint(raw_host, raw_port, default_port):
    """NetworkEndpoint.parse: host string + port string -> (host, port)."""
    host = str(raw_host).strip()
    if not host:
        raise DecodeError("INVALID_HOST",
                          "Adresse serveur invalide : indiquez un hôte sans URL ni chemin.")
    for ch in host:
        if ch.isspace() or ch in "/@?#\\":
            raise DecodeError(
                "INVALID_HOST",
                "Adresse serveur invalide : indiquez un hôte sans URL ni chemin.")
    port_from_host = None
    if host.startswith("["):
        m = re.fullmatch(r"\[([^\]]+)\](?::([0-9]+))?", host)
        if not m:
            raise DecodeError(
                "INVALID_HOST",
                "Adresse IPv6 invalide. Utilisez [adresse]:port ou le champ PORT séparé.")
        host = m.group(1)
        if ":" not in host:
            raise DecodeError("INVALID_HOST", "Adresse IPv6 invalide.")
        if m.group(2):
            port_from_host = _port_or_error(m.group(2))
    else:
        ncolon = host.count(":")
        if ncolon == 1:
            host, p = host.split(":")
            if not host:
                raise DecodeError("INVALID_HOST", "Adresse serveur manquante.")
            port_from_host = _port_or_error(p)
        elif ncolon > 1:
            try:
                if urlsplit("tcp://[" + host + "]").hostname is None:
                    raise DecodeError("INVALID_HOST", "Adresse IPv6 invalide.")
            except DecodeError:
                raise
            except Exception:
                raise DecodeError("INVALID_HOST", "Adresse IPv6 invalide.")
        elif "[" in host or "]" in host:
            raise DecodeError("INVALID_HOST", "Adresse serveur invalide.")
    p2 = None
    if raw_port is not None:
        s = str(raw_port).strip()
        if s:
            p2 = _port_or_error(s)
    if port_from_host is not None and p2 is not None and port_from_host != p2:
        raise DecodeError(
            "PORT_CONFLICT",
            f"Ports contradictoires : {port_from_host} dans SERVEUR et {p2} dans PORT.")
    port = (port_from_host if port_from_host is not None
            else (p2 if p2 is not None else default_port))
    return host, port


def _normalize(config):
    host, port = _parse_endpoint(config["server"], config["port"],
                                 DEFAULT_PORT[config["protocol"]])
    out = dict(config)
    out["server"] = host
    out["port"] = str(port)
    return out


def _validate(config):
    """XrayConfig.validate(cfg, forImport=true). Returns error str or None."""
    if config.get("sharePolicy") is not None:
        exp = config["sharePolicy"].get("expiresAt") or 0
        if exp and time.time() * 1000 >= exp:
            return "Ce profil a expiré (date vérifiée hors ligne)."
    if config["protocol"] == "DNS_ONLY":
        return "DNS_ONLY n'est pas encore pris en charge par le moteur Xray"
    if not config["server"].strip():
        return "Serveur manquant"
    try:
        p = int(config["port"])
    except ValueError:
        return "Port invalide : " + config["port"]
    if not 1 <= p <= 65535:
        return "Port invalide : " + config["port"]
    try:
        _parse_endpoint(config["server"], config["port"],
                        DEFAULT_PORT[config["protocol"]])
    except DecodeError as exc:
        return str(exc)
    if not config["uuid"].strip() and config["protocol"] not in SIMPLE_PROTOCOLS:
        return SECRET_LABEL.get(config["protocol"], "Secret") + " manquant"
    if any(ch.isspace() for ch in config["server"]):
        return "Adresse serveur invalide (sans https:// ni chemin)."
    if "/" in config["server"] or "@" in config["server"]:
        return "Adresse serveur invalide (sans https:// ni chemin)."
    if config["vmessSecurity"] not in VMESS_SECURITY:
        return "Chiffrement VMess non pris en charge."
    if config["tlsPeerPin"].strip():
        for part in config["tlsPeerPin"].split(","):
            if not re.fullmatch(r"[a-fA-F0-9]{64}", part.strip().replace(":", "")):
                return ("Empreinte certificat TLS invalide : SHA256 hexadécimal "
                        "de 64 caractères attendu.")
    if (config["protocol"] == "SHADOWSOCKS"
            and config["ssMethod"] not in SS_METHODS):
        return "Méthode Shadowsocks non prise en charge."
    if config["protocol"] in ("SSH", "SSH_THROUGH"):
        if not config["sshUser"].strip():
            return "Nom d'utilisateur SSH manquant."
    if config["protocol"] == "SSH_THROUGH" and not config["proxy"]:
        return "SSH Through nécessite Proxy Target activé."
    if config["proxy"] and config["protocol"] not in SIMPLE_PROTOCOLS:
        if not config["proxyHost"].strip() or not config["payload"].strip():
            return ("Proxy Target activé : renseignez le proxy et le payload, "
                    "ou désactivez l'interrupteur.")
    return None


# ------------------------------------------------------------ link parsers
def _uri_config(raw: str):
    """ConfigImporter.uriConfig: vless://, trojan://, ssh:// (shared body)."""
    # java.net.URI(raw) rejects raw non-ASCII / spaces before anything else.
    if any(ord(ch) > 127 for ch in raw) or " " in raw:
        raise DecodeError("INVALID_URI", "URISyntaxException: illegal char")
    try:
        u = urlsplit(raw)
    except ValueError as exc:
        raise DecodeError("INVALID_URI", f"URISyntaxException: {exc}")
    scheme = (u.scheme or "").lower()
    proto_map = {"vless": "VLESS", "trojan": "TROJAN", "ssh": "SSH"}
    if scheme not in proto_map:
        raise DecodeError(
            "UNSUPPORTED_LINK",
            "Lien non pris en charge : VMess, VLESS, Trojan, Shadowsocks ou SSH requis.")
    protocol = proto_map[scheme]
    query = {}
    if u.query:
        for part in u.query.split("&"):
            if not part.strip():
                continue
            k, _, v = part.partition("=")
            query[_decode_url(k)] = _decode_url(v)
    typ = query.get("type", query.get("network", "tcp"))
    sec = query.get("security")
    if sec is None:
        sec = "tls" if protocol == "TROJAN" else "none"
    if typ not in ("tcp", "raw", "ws"):
        raise DecodeError("UNSUPPORTED_TRANSPORT",
                          f"Transport {typ} non pris en charge (TCP/WS uniquement).")
    if sec not in ("tls", "none", ""):
        raise DecodeError("UNSUPPORTED_SECURITY",
                          f"Sécurité {sec} non prise en charge. Le profil n'a pas été modifié.")
    flow = query.get("flow")
    if flow is not None and flow.strip():
        raise DecodeError("UNSUPPORTED_FLOW", "VLESS flow/XTLS non pris en charge.")
    header_type = query.get("headerType")
    if (header_type is not None and header_type.strip()
            and header_type != "none"):
        raise DecodeError("UNSUPPORTED_HEADER", "En-tête TCP spécifique non pris en charge.")
    enc = query.get("encryption")
    if enc is not None and enc.strip() and enc != "none":
        raise DecodeError("UNSUPPORTED_ENCRYPTION", "Chiffrement VLESS non pris en charge.")
    netloc = u.netloc
    raw_userinfo = netloc.rsplit("@", 1)[0] if "@" in netloc else ""
    if not raw_userinfo:
        raise DecodeError("MISSING_CREDENTIALS", "Identifiants absents du lien.")
    host = u.hostname
    if not host:
        raise DecodeError("INVALID_HOST", "Adresse serveur invalide.")
    try:
        port = u.port
    except ValueError:
        raise DecodeError("INVALID_PORT", "Port invalide")
    if port is None:
        port = DEFAULT_PORT[protocol]
    is_ssh = protocol == "SSH"
    if is_ssh:
        ssh_user = _decode_url(raw_userinfo.split(":", 1)[0])
        uuid = _decode_url(raw_userinfo.split(":", 1)[1]) if ":" in raw_userinfo else ""
    else:
        ssh_user = ""
        uuid = _decode_url(raw_userinfo)
    name = _decode_url(u.fragment) if u.fragment else host
    if not name.strip():
        name = host
    return _config(name, protocol, host, port, uuid,
                   websocket=(typ == "ws"), ws_path=query.get("path", "/"),
                   ws_host=query.get("host", ""), tls=(sec == "tls"),
                   sni=query.get("sni", query.get("peer", "")),
                   ssh_user=ssh_user, ssh_fp=query.get("fingerprint", ""),
                   allow_insecure=_parse_bool(
                       query.get("allowInsecure", query.get("insecure"))),
                   tls_fp=query.get("fp", ""), tls_alpn=_parse_alpn(query.get("alpn")),
                   tls_pin=query.get("pcs", query.get("pinnedPeerCertSha256", "")))


def _vmess_config(obj: dict):
    """ConfigImporter.vmess(JSONObject)."""
    net = str(obj.get("net", "tcp")).lower()
    if net not in ("tcp", "ws", "raw"):
        raise DecodeError("UNSUPPORTED_TRANSPORT",
                          f"VMess : transport {net} non pris en charge.")
    if obj.get("tls", "") not in ("", "none", "tls"):
        raise DecodeError("UNSUPPORTED_SECURITY", "Sécurité VMess non prise en charge.")
    try:
        aid = int(obj.get("aid", 0))
    except (TypeError, ValueError):
        aid = 0
    if aid != 0:
        raise DecodeError("UNSUPPORTED_VMESS",
                          "Ancien VMess alterId non pris en charge ; utilisez AEAD (aid=0).")
    if obj.get("type", "none") not in ("", "none"):
        raise DecodeError("UNSUPPORTED_VMESS", "En-tête VMess spécifique non pris en charge.")
    ps = obj.get("ps", "VMess") or "VMess"
    if not str(ps).strip():
        ps = "VMess"
    try:
        server = str(obj["add"]).strip()
        uuid = str(obj["id"]).strip()
    except KeyError as exc:
        raise DecodeError("MISSING_FIELD", f"VMess: champ manquant {exc}")
    insecure = obj.get("insecure", obj.get("allowInsecure"))
    return _config(str(ps), "VMESS", server, str(obj.get("port", "443")), uuid,
                   websocket=(net == "ws"), ws_path=obj.get("path", "/"),
                   ws_host=obj.get("host", ""), tls=(obj.get("tls") == "tls"),
                   sni=obj.get("sni", ""), vmess_sec=obj.get("scy", "auto"),
                   allow_insecure=_parse_bool(insecure),
                   tls_fp=obj.get("fp", ""),
                   tls_alpn=_parse_alpn(obj.get("alpn")),
                   tls_pin=obj.get("pinnedPeerCertSha256", obj.get("pcs", "")))


def _shadowsocks_config(raw: str):
    """ConfigImporter.shadowsocks(String)."""
    after = raw.split("://", 1)[1]
    name = _decode_url(after.split("#", 1)[1]) if "#" in after else ""
    before_hash = after.split("#", 1)[0]
    if "plugin=" in before_hash:
        raise DecodeError("UNSUPPORTED_SS", "Plugin Shadowsocks non pris en charge.")
    s = before_hash.split("?", 1)[0].rstrip("/")
    if "@" not in s:
        s = _b64decode_text(s)
    before_at = s.rsplit("@", 1)[0]
    userinfo = _decode_url(before_at) if ":" in before_at else _b64decode_text(before_at)
    if ":" not in userinfo or "@" not in s:
        raise DecodeError("INVALID_SS", "Identifiants Shadowsocks invalides.")
    hostport = s.rsplit("@", 1)[1]
    u = urlsplit("ss://" + hostport)
    if not u.hostname:
        raise DecodeError("INVALID_HOST", "Serveur Shadowsocks invalide.")
    try:
        port = u.port
    except ValueError:
        raise DecodeError("INVALID_PORT", "Port invalide")
    if not name.strip():
        name = "Shadowsocks"
    method, _, password = userinfo.partition(":")
    return _config(name, "SHADOWSOCKS", u.hostname, port or 8388, password,
                   tls=False, ss_method=method)


# ------------------------------------------------------- DarkTunnel / JSON
def _config_from_json(obj: dict):
    """TunnelConfig.Companion.fromJson + normalizeOrKeep."""
    def opt(key, default=""):
        v = obj.get(key, default)
        return default if v is None else v
    protocol_name = opt("protocol", "VLESS")
    protocol = {"VLESS": "VLESS", "VMESS": "VMESS", "TROJAN": "TROJAN",
                "SHADOWSOCKS": "SHADOWSOCKS", "SSH": "SSH",
                "SSH_THROUGH": "SSH_THROUGH", "DNSTT": "DNSTT",
                "V2RAY": "V2RAY", "HTTP_PROXY": "HTTP_PROXY",
                "SOCKS5": "SOCKS5", "PAYLOAD": "PAYLOAD",
                "SNI_HOST": "SNI_HOST", "DNS_ONLY": "DNS_ONLY"}.get(
                    str(protocol_name).upper())
    if protocol is None:
        # Protocol.fromName also matches the display label, case-insensitive.
        labels = {"vless": "VLESS", "vmess": "VMESS", "trojan": "TROJAN",
                  "shadowsocks": "SHADOWSOCKS", "ssh": "SSH"}
        protocol = labels.get(str(protocol_name).lower())
    if protocol is None:
        raise DecodeError("UNKNOWN_PROTOCOL", f"Protocole inconnu : {protocol_name}")
    share_policy = None
    sp = obj.get("sharePolicy")
    if isinstance(sp, dict):
        share_policy = {"id": sp.get("id", ""), "locked": bool(sp.get("locked", False)),
                        "expiresAt": sp.get("expiresAt", 0),
                        "deviceId": sp.get("deviceId", ""),
                        "hourStart": sp.get("hourStart", -1),
                        "hourEnd": sp.get("hourEnd", -1),
                        "message": sp.get("message", "")}
    cfg = _config(opt("name", "DGM Profile"), protocol, opt("server", ""),
                  opt("port", str(DEFAULT_PORT[protocol])), opt("uuid", ""),
                  websocket=bool(obj.get("websocket", False)),
                  ws_path=opt("wsPath", "/"), ws_host=opt("wsHost", ""),
                  tls=bool(obj.get("tls", True)), sni=opt("sni", ""),
                  mux=bool(obj.get("mux", False)),
                  mux_conc=opt("muxConcurrency", "8"),
                  proxy=bool(obj.get("proxy", False)),
                  proxy_host=opt("proxyHost", ""), proxy_port=opt("proxyPort", ""),
                  payload=opt("payload", ""), ss_method=opt("ssMethod", "aes-256-gcm"),
                  ssh_user=opt("sshUser", ""), ssh_fp=opt("sshFingerprint", ""),
                  vmess_sec=opt("vmessSecurity", "auto"),
                  allow_insecure=_parse_bool(obj.get("allowInsecure")),
                  tls_fp=opt("tlsFingerprint", ""), tls_alpn=opt("tlsAlpn", ""),
                  tls_pin=opt("tlsPeerPin", ""), share_policy=share_policy)
    port_was_provided = bool(obj.get("port")) and str(obj.get("port")).strip() != ""
    try:
        host, port = _parse_endpoint(cfg["server"],
                                     cfg["port"] if port_was_provided else None,
                                     DEFAULT_PORT[protocol])
        cfg["server"], cfg["port"] = host, str(port)
    except DecodeError:
        pass  # normalizeOrKeep keeps the config as-is on failure
    return cfg


def _node_to_config(name, is_trojan, node: dict):
    """TunnelConfig.Companion.nodeToConfig (DarkTunnel node form)."""
    v2ray = node.get("v2rayConfig")
    if not isinstance(v2ray, dict):
        return None
    inject = node.get("injectConfig") if isinstance(node.get("injectConfig"), dict) else None
    host = v2ray.get("host", "")
    if not isinstance(host, str) or not host.strip():
        return None
    sni_full = v2ray.get("serverNameIndication", host) or host
    sni = str(sni_full).split(":", 1)[0]
    transport = str(v2ray.get("transportNetwork", "Websocket")).lower()
    if transport not in ("ws", "websocket", "tcp", "raw"):
        raise DecodeError("UNSUPPORTED_TRANSPORT",
                          f"Transport DarkTunnel non pris en charge : {transport}")
    proxy_host = ""
    if inject is not None:
        proxy_host = str(inject.get("proxyHost", "") or "").strip()
    payload = ""
    if inject is not None:
        payload = inject.get("payload", "") or ""
    proxy = bool(inject is not None and inject.get("enabled", False)
                 and proxy_host and payload)
    protocol = "TROJAN" if is_trojan else "VLESS"
    cfg_name = name + " (Trojan)" if is_trojan else name
    port = int(v2ray.get("port", 443))
    uuid = v2ray.get("uuid", "") or v2ray.get("password", "") or ""
    ws_path = v2ray.get("wsPath", "/") or "/"
    if not str(ws_path).strip():
        ws_path = "/"
    tls = True
    if port != 443:
        tls = bool(str(v2ray.get("serverNameIndication", "")).strip())
    return _config(cfg_name, protocol, host, port, str(uuid),
                   websocket=(transport in ("ws", "websocket")), ws_path=str(ws_path),
                   ws_host=v2ray.get("wsHeaderHost", ""), tls=tls, sni=sni,
                   proxy=proxy, proxy_host=proxy_host,
                   proxy_port=(str(inject.get("proxyPort", "8080"))
                               if inject is not None else "8080"),
                   payload=str(payload))


def _parse_dark_tunnel(text: str):
    """TunnelConfig.Companion.parseDarkTunnel -> (name, config, alt)."""
    body = text.strip()
    for prefix in ("darktunnel://", "dgmtunnel://"):
        if body.lower().startswith(prefix):
            body = body[len(prefix):]
            break
    body = body.split("#", 1)[0].strip()
    try:
        obj = json.loads(_b64decode_text(body))
    except Exception as exc:
        raise DecodeError("INVALID_DARKTUNNEL", f"DarkTunnel Base64/JSON invalide: {exc}")
    if not isinstance(obj, dict):
        raise DecodeError("INVALID_DARKTUNNEL", "DarkTunnel: JSON no es un objeto.")
    if "server" in obj:
        cfg = _config_from_json(obj)
        return cfg["name"], cfg, None
    name = obj.get("name", "") or "DGM Profile"
    type_upper = str(obj.get("type", "VLESS")).upper()
    vmess_node = obj.get("vmessTunnelConfig")
    vless_node = obj.get("vlessTunnelConfig")
    trojan_node = obj.get("trojanTunnelConfig")
    vmess_cfg = (_node_to_config(name, False, vmess_node)
                 if isinstance(vmess_node, dict) else None)
    if vmess_cfg is not None:
        vmess_cfg["protocol"] = "VMESS"
    vless_cfg = (_node_to_config(name, False, vless_node)
                 if isinstance(vless_node, dict) else None)
    trojan_cfg = (_node_to_config(name, True, trojan_node)
                  if isinstance(trojan_node, dict) else None)
    if "VMESS" in type_upper:
        first, second = vmess_cfg, trojan_cfg
    elif "TROJAN" in type_upper:
        first, second = trojan_cfg, vless_cfg
    else:
        first, second = vless_cfg, trojan_cfg
    if first is None:
        if second is None:
            return None
        first = second
        second = None
    if second is first:
        second = None
    return name, first, second


def _parse_one(raw: str):
    """ConfigImporter.parseOne -> Profile (raises DecodeError on failure)."""
    low = raw.strip().lower()
    if low.startswith("darktunnel://") or low.startswith("dgmtunnel://"):
        parsed = _parse_dark_tunnel(raw.strip())
        if parsed is None:
            raise DecodeError("INVALID_DARKTUNNEL", "Lien DarkTunnel invalide ou incomplet.")
        name, cfg, alt = parsed
        return _profile(cfg, alt=alt, profile_id="import") | {"name": name}
    if raw.strip().startswith("{"):
        try:
            obj = json.loads(raw)
        except ValueError as exc:
            raise DecodeError("INVALID_JSON", f"JSON invalide ou fichier tronqué: {exc}")
        if not isinstance(obj, dict):
            raise DecodeError("INVALID_JSON", "JSON invalide ou fichier tronqué.")
        if "ciphertext" in obj or "enc" in obj:
            raise DecodeError("ENCRYPTED_EYJ",
                              "EYJ chiffré : ce format protégé nécessite le déchiffrement "
                              "de l'application d'origine.")
        if "config" in obj:
            if not isinstance(obj["config"], dict):
                raise DecodeError("INVALID_JSON", "JSON invalide ou fichier tronqué.")
            cfg = _config_from_json(obj["config"])
            alt = None
            if isinstance(obj.get("alt"), dict):
                alt = _config_from_json(obj["alt"])
            return {"id": obj.get("id", ""), "name": obj.get("name", "Profil"),
                    "config": cfg, "alt": alt}
        if "server" in obj:
            return _profile(_config_from_json(obj))
        if "add" in obj and "id" in obj:
            return _profile(_vmess_config(obj))
        if any(k in obj for k in ("vlessTunnelConfig", "trojanTunnelConfig",
                                  "vmessTunnelConfig")):
            encoded = base64.b64encode(raw.encode("utf-8")).decode("ascii")
            return _parse_one("darktunnel://" + encoded)
        raise DecodeError(
            "UNKNOWN_JSON",
            "JSON non reconnu. Exportez un profil DGMTunnel ou un lien VPN "
            "(pas une configuration Xray complète).")
    if low.startswith("vmess://"):
        body = raw.strip().split("://", 1)[1].split("#", 1)[0]
        try:
            obj = json.loads(_b64decode_text(body))
        except Exception as exc:
            raise DecodeError("INVALID_VMESS", f"VMess Base64/JSON invalide: {exc}")
        if not isinstance(obj, dict):
            raise DecodeError("INVALID_VMESS", "VMess: JSON no es un objeto.")
        return _profile(_vmess_config(obj))
    if low.startswith("ss://"):
        return _profile(_shadowsocks_config(raw.strip()))
    return _profile(_uri_config(raw.strip()))


def _unwrap(raw: str) -> str:
    """ConfigImporter.unwrap: JSON/array as-is, a link list as-is, else Base64."""
    text = raw.strip().removeprefix("\ufeff")
    if not text.strip():
        raise DecodeError("EMPTY", "Le presse-papiers ou le fichier est vide.")
    if text.startswith("{") or text.startswith("["):
        return text
    for line in text.splitlines():
        stripped = line.strip()
        for scheme in SCHEMES:
            if stripped.lower().startswith(scheme + "://"):
                return text
    try:
        decoded = _b64decode_text(text).strip()
    except Exception:
        decoded = None
    if decoded is not None:
        return decoded
    raise DecodeError(
        "UNKNOWN_FORMAT",
        "Format inconnu ou EYJ chiffré. Seuls JSON, Base64 JSON et liens VPN "
        "sont lisibles ; aucun déchiffrement propriétaire.")


def _json_doc(data: bytes):
    try:
        doc = json.loads(data.decode("utf-8-sig"))
    except (ValueError, UnicodeError) as exc:
        raise DecodeError("INVALID_JSON", f"JSON invalido: {exc}")
    if not isinstance(doc, (dict, list)):
        raise DecodeError("WRONG_DOCUMENT", "El documento debe ser un objeto o array JSON.")
    return doc


def parse_text(raw: str, limit: int = PARSE_LIMIT):
    """ConfigImporter.parse(raw, limit) -> (profiles, errors).

    profiles: list of Profile dicts in feed order (exact-duplicate configs
    are skipped, see module docstring). errors: ["Entree N : <message>"].
    """
    if len(raw.encode("utf-8")) > MAX_BYTES:
        return [], ["Fichier trop volumineux (4 Mo maximum)."]
    try:
        text = _unwrap(raw.strip().removeprefix("\ufeff"))
    except DecodeError as exc:
        return [], [str(exc)]
    if text.startswith("["):
        try:
            items = json.loads(text)
            entries = [json.dumps(x, ensure_ascii=False) if not isinstance(x, str) else x
                       for x in items]
        except ValueError:
            return [], ["JSON invalide ou fichier tronqué."]
    elif text.startswith("{"):
        entries = [text]
    else:
        entries = [line.strip() for line in text.splitlines()
                   if line.strip() and not line.strip().startswith("#")]
    profiles, errors = [], []
    for index, entry in enumerate(entries):
        if len(profiles) >= limit:
            break
        try:
            profile = _parse_one(entry)
            config = _normalize(profile["config"])
            profile = dict(profile)
            profile["config"] = config
            if profile.get("alt") is not None:
                profile["alt"] = _normalize(profile["alt"])
            err = _validate(config)
            if err is not None:
                raise DecodeError("VALIDATION_FAILED", err)
            if profile.get("alt") is not None:
                err_alt = _validate(profile["alt"])
                if err_alt is not None:
                    raise DecodeError("VALIDATION_FAILED", "Alternative : " + err_alt)
            if not any(p["config"] == config for p in profiles):
                profile["source_uri"] = entry
                profiles.append(profile)
        except DecodeError as exc:
            errors.append(f"Entrée {index + 1} : {exc}")
        except (ValueError, KeyError, TypeError, binascii.Error,
                UnicodeDecodeError) as exc:
            errors.append(f"Entrée {index + 1} : {exc}")
    return profiles, errors


def apply_free_server_catalog(profiles):
    """FreeServerCatalog.fetch post-processing: filter, dedupe, take 40."""
    kept = [p for p in profiles
            if p["config"]["protocol"] not in ("SSH", "SSH_THROUGH")
            and not p["config"]["proxy"]]
    seen, deduped = set(), []
    for p in kept:
        c = p["config"]
        key = (c["protocol"], c["server"], c["port"], c["uuid"])
        if key in seen:
            continue
        seen.add(key)
        deduped.append(p)
    out = []
    for i, p in enumerate(deduped[:CATALOG_TAKE]):
        config = dict(p["config"])
        config["name"] = p["name"][:90]
        out.append({"id": f"public-{i}", "name": p["name"][:90],
                    "config": config, "alt": p.get("alt"),
                    "source_uri": p.get("source_uri", "")})
    return out


def decode_feed_catalog(data: bytes, fetched_at: str | None = None) -> dict:
    """Feed bytes -> catalog dict, exactly as FreeServerCatalog does.

    Bridge entry point used by server_catalog_decoder.run(): the broker
    downloads the feed and hands the raw bytes here. Parses the first
    500 profiles, filters, dedupes and takes the first 40 (all fields
    in clear text; the feed is plain text, no encryption). The snapshot
    has NO catalog version number: it is identified by fetched_at (UTC,
    stamped here when not supplied). The feed is ROTATING: a later
    re-fetch returns a different 40. Result has no download APIs, only
    the decoded catalog data. Raises DecodeError on empty/oversize
    input or undecodable text; an empty profile list is NOT an error
    here (the adapter rejects it) - a feed with zero parseable lines
    still returns its counts.
    """
    if not isinstance(data, (bytes, bytearray)) or not data:
        raise DecodeError("EMPTY_FEED", "Feed vacío.")
    if len(data) > MAX_BYTES:
        raise DecodeError("SIZE_LIMIT", "La entrada supera el límite de tamaño.")
    text = data.decode("utf-8")
    feed_lines = len(text.splitlines())
    feed_entries = len([line for line in text.splitlines()
                        if line.strip() and not line.strip().startswith("#")])
    profiles, errors = parse_text(text, limit=PARSE_LIMIT)
    for prof in profiles:
        if "source_uri" not in prof:
            prof["source_uri"] = ""
    final_profiles = apply_free_server_catalog(profiles)
    # Keep the source link of each kept profile for the complete copy.
    src_by_key = {}
    for prof in profiles:
        cfg = prof["config"]
        src_by_key.setdefault(
            (cfg["protocol"], cfg["server"], cfg["port"], cfg["uuid"]),
            prof.get("source_uri", ""))
    for prof in final_profiles:
        cfg = prof["config"]
        prof["source_uri"] = src_by_key.get(
            (cfg["protocol"], cfg["server"], cfg["port"], cfg["uuid"]), "")
    if fetched_at is None:
        fetched_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    return {"app": "DGM Tunnel", "package": APP_PACKAGE,
            "versionName": APP_VERSION_NAME, "versionCode": APP_VERSION_CODE,
            "source": SOURCE_NAME, "fetched_at": fetched_at,
            "feed_lines": feed_lines, "feed_entries": feed_entries,
            "parsed_profiles": len(profiles),
            "rejected_entries": len(errors),
            "rejected_reasons": _count_reasons(errors),
            "profiles": final_profiles}


# ------------------------------------------------------------------- share
def _share_aad(envelope: dict) -> bytes:
    keys = ["format", "version", "id", "createdAt", "expiresAt", "locked",
            "passwordProtected", "iterations", "salt", "iv"]
    if int(envelope.get("version", 1)) >= 2:
        keys += ["deviceId", "hourStart", "hourEnd", "message"]
    lines = []
    for key in keys:
        value = envelope.get(key)
        if isinstance(value, bool):
            value = "true" if value else "false"
        lines.append(f"{key}={value}")
    return "\n".join(lines).encode("utf-8")


def open_share(raw: str, password: str, now_ms: int | None = None):
    """ShareCodec.open: DGMTUNNEL_SHARE v2 envelope -> TunnelConfig dict.

    Returns (config, envelope-meta). Raises DecodeError on expiry, wrong
    password / tampering, or unsupported version. Needs PyCryptodome.
    """
    try:
        from Crypto.Cipher import AES as _AES
    except Exception:
        raise DecodeError("FAST_CRYPTO_REQUIRED",
                          "Abrir un share protegido requiere PyCryptodome.")
    text = raw.strip()
    if text.lower().startswith("dgmtunnel://share/"):
        payload_b64 = text.split("/share/", 1)[1].strip()
        text = _b64decode_text(payload_b64)
    elif not text.startswith("{"):
        text = _b64decode_text(text)
    try:
        envelope = json.loads(text)
    except ValueError as exc:
        raise DecodeError("INVALID_JSON", f"Share: JSON invalide: {exc}")
    if envelope.get("format") != SHARE_FORMAT:
        raise DecodeError("WRONG_FORMAT", "Version de partage non prise en charge.")
    version = int(envelope.get("version", 0))
    if not 1 <= version < 3:
        raise DecodeError("WRONG_FORMAT", "Version de partage non prise en charge.")
    if now_ms is None:
        now_ms = int(time.time() * 1000)
    expires_at = int(envelope.get("expiresAt", 0) or 0)
    if expires_at < 0 or (expires_at != 0 and now_ms >= expires_at):
        raise DecodeError("EXPIRED", "Ce profil a expiré (vérification hors ligne).")
    payload = _b64decode_bytes(envelope["payload"])
    if envelope.get("passwordProtected"):
        if password is None:
            raise DecodeError("PASSWORD_REQUIRED", "SharePasswordRequired")
        if len(password) > 256 or int(envelope.get("iterations", 0)) != SHARE_ITERATIONS:
            raise DecodeError("INVALID_SHARE_PARAMS", "Paramètres de protection invalides.")
        salt = _b64decode_bytes(envelope["salt"])
        iv = _b64decode_bytes(envelope["iv"])
        if len(salt) != 16 or len(iv) != 12:
            raise DecodeError("INVALID_SHARE_PARAMS", "Protection invalide.")
        key = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt,
                                  SHARE_ITERATIONS, dklen=32)
        cipher = _AES.new(key, _AES.MODE_GCM, nonce=iv)
        cipher.update(_share_aad(envelope))
        try:
            plain = cipher.decrypt_and_verify(payload[:-16], payload[-16:])
        except ValueError:
            raise DecodeError("WRONG_PASSWORD",
                              "Mot de passe incorrect ou fichier altéré.")
    else:
        plain = payload
    try:
        cfg = _config_from_json(json.loads(plain.decode("utf-8")))
    except (ValueError, UnicodeDecodeError) as exc:
        raise DecodeError("INVALID_JSON", f"Share: JSON interne invalide: {exc}")
    cfg["sharePolicy"] = {"id": envelope.get("id", ""),
                          "locked": bool(envelope.get("locked", False)),
                          "expiresAt": expires_at,
                          "deviceId": envelope.get("deviceId", ""),
                          "hourStart": envelope.get("hourStart", -1),
                          "hourEnd": envelope.get("hourEnd", -1),
                          "message": envelope.get("message", "")}
    err = _validate(cfg)
    if err is not None:
        raise DecodeError("VALIDATION_FAILED", err)
    meta = {"id": envelope.get("id", ""), "locked": bool(envelope.get("locked", False)),
            "expiresAt": expires_at, "deviceId": envelope.get("deviceId", ""),
            "hourStart": envelope.get("hourStart", -1),
            "hourEnd": envelope.get("hourEnd", -1),
            "message": envelope.get("message", ""),
            "device_binding": ("no verificado en este entorno: el sobre trae "
                               "deviceId=%r" % envelope.get("deviceId", ""))}
    return cfg, meta


def seal_share(config, password, locked=False, expires_at=0, now_ms=None,
               device_id="", hour_start=-1, hour_end=-1, message=""):
    """ShareCodec.create (for --self-test round-trip only)."""
    import uuid as _uuid
    try:
        from Crypto.Cipher import AES as _AES
    except Exception:
        raise DecodeError("FAST_CRYPTO_REQUIRED",
                          "Crear un share requiere PyCryptodome.")
    import os as _os
    if now_ms is None:
        now_ms = int(time.time() * 1000)
    envelope = {"format": SHARE_FORMAT, "version": 2,
                "id": str(_uuid.uuid4()), "createdAt": now_ms,
                "expiresAt": expires_at, "locked": locked,
                "passwordProtected": password is not None,
                "iterations": SHARE_ITERATIONS if password is not None else 0,
                "salt": "", "iv": "", "deviceId": device_id,
                "hourStart": hour_start, "hourEnd": hour_end,
                "message": message[:500]}
    plain = json.dumps(config, ensure_ascii=False).encode("utf-8")
    if password is not None:
        salt = _os.urandom(16)
        iv = _os.urandom(12)
        envelope["salt"] = base64.b64encode(salt).decode("ascii")
        envelope["iv"] = base64.b64encode(iv).decode("ascii")
        key = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt,
                                  SHARE_ITERATIONS, dklen=32)
        cipher = _AES.new(key, _AES.MODE_GCM, nonce=iv)
        cipher.update(_share_aad(envelope))
        ct, tag = cipher.encrypt_and_digest(plain)
        payload = ct + tag
    else:
        payload = plain
    envelope["payload"] = base64.b64encode(payload).decode("ascii")
    return json.dumps(envelope, ensure_ascii=False)


# -------------------------------------------------------------------- fetch
def fetch_feed(url: str = FEED_URL, retries: int = 8) -> bytes:
    """GET exactly as FreeServerCatalog.fetch does: no body, UA DGMTunnel/1.5,
    15 s connect/read timeouts, no redirect following, 4 MiB cap.
    Implemented with urllib (the VM egress proxy closes http.client
    CONNECT tunnels with a hand-built Proxy-Authorization header, while
    urllib's env proxy handling works). The request on the wire is the
    same: GET <path>, Host, User-Agent DGMTunnel/1.5, no body."""
    import urllib.request as _urlreq
    parsed = urlsplit(url)
    if parsed.scheme != "https" or not parsed.hostname:
        raise DecodeError("INVALID_URL", "Se requiere una URL HTTPS.")

    class _NoRedirect(_urlreq.HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, headers, newurl):
            raise DecodeError("DOWNLOAD_FAILED",
                              f"El feed redirigió (HTTP {code}); la app no sigue "
                              "redirecciones ('Source indisponible').")

    opener = _urlreq.build_opener(_NoRedirect, _urlreq.ProxyHandler())
    request = _urlreq.Request(url, headers={"User-Agent": USER_AGENT},
                              method="GET")
    last_error: Exception | None = None
    for attempt in range(max(1, retries)):
        try:
            with opener.open(request, timeout=15) as resp:
                if resp.status != 200:
                    raise DecodeError("DOWNLOAD_FAILED",
                                      f"El feed devolvió HTTP {resp.status} "
                                      "(la app lanza 'Source indisponible').")
                raw = resp.read(MAX_BYTES + 1)
        except DecodeError:
            raise
        except (OSError, ValueError, HTTPError, URLError, HTTPException) as exc:
            last_error = exc
            if attempt + 1 < max(1, retries):
                time.sleep(1 + attempt)
            continue
        if not raw or len(raw) > MAX_BYTES:
            raise DecodeError("DOWNLOAD_FAILED", "Feed vacío o superior a 4 MiB.")
        return raw
    raise DecodeError("DOWNLOAD_FAILED",
                      "No se pudo descargar el feed mediante HTTPS "
                      f"(último error: {last_error}).") from last_error


# ------------------------------------------------------------------ redact
_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


def _is_ipv4(value: str) -> bool:
    parts = value.split(".")
    if len(parts) != 4:
        return False
    try:
        return all(0 <= int(p) <= 255 and str(int(p)) == p for p in parts)
    except ValueError:
        return False


def redact(doc):
    """Recursive redaction: any IPv4 literal -> REDACTED, uuid/password
    fields emptied, source URIs dropped. Returns (redacted, ip_count_left)."""
    def scrub(value):
        if isinstance(value, str):
            return _IPV4_RE.sub(
                lambda m: "REDACTED" if _is_ipv4(m.group(0)) else m.group(0), value)
        if isinstance(value, dict):
            out = {}
            for k, v in value.items():
                if k in ("source_uri",):
                    continue
                if k in ("uuid", "password"):
                    out[k] = ""
                else:
                    out[k] = scrub(v)
            return out
        if isinstance(value, list):
            return [scrub(v) for v in value]
        return value
    red = scrub(doc)
    left = len(_IPV4_RE.findall(json.dumps(red, ensure_ascii=False)))
    # also count real IPv4s (the regex above can match version-like numbers)
    left = sum(1 for m in _IPV4_RE.finditer(json.dumps(red, ensure_ascii=False))
               if _is_ipv4(m.group(0)))
    return red, left


# --------------------------------------------------------------------- main
def _validate_json(doc):
    pending, count = [(doc, 0)], 0
    while pending:
        value, depth = pending.pop()
        count += 1
        if depth > MAX_DEPTH or count > MAX_NODES:
            raise DecodeError("SIZE_LIMIT", "El JSON supera el límite de complejidad.")
        if isinstance(value, dict):
            pending.extend((v, depth + 1) for v in value.values())
        elif isinstance(value, list):
            pending.extend((v, depth + 1) for v in value)
        elif isinstance(value, float) and not math.isfinite(value):
            raise DecodeError("INVALID_JSON", "Número JSON no finito.")


def _self_test() -> int:
    import os as _os
    checks = {}
    # 1. Subscription sample: one of each parseable scheme.
    sample = "\n".join([
        "ss://YWVzLTI1Ni1nY206aXR6dnBuQDMyMQ@57.131.27.21:8388#Italy",
        "vless://11111111-1111-4111-8111-111111111111@example.com:443"
        "?security=tls&type=ws&path=%2Fws&host=example.com&sni=example.com#WsTls",
        "trojan://secret@example.org:443?security=tls&type=tcp#TrojanTcp",
        "vmess://" + base64.b64encode(json.dumps(
            {"v": "2", "ps": "VmessWs", "add": "vm.example.net", "port": "443",
             "id": "22222222-2222-4222-8222-222222222222", "aid": "0",
             "net": "ws", "type": "none", "host": "vm.example.net",
             "path": "/v", "tls": "tls", "sni": "vm.example.net",
             "scy": "auto"}).encode()).decode(),
        "vless://33333333-3333-4333-8333-333333333333@10.0.0.1:443"
        "?security=reality&encryption=none&type=tcp#RealityRejected",
    ])
    profiles, errors = parse_text(sample)
    checks["sample_parsed"] = len(profiles)
    checks["sample_errors"] = len(errors)
    assert len(profiles) == 4, f"sample: {len(profiles)} profiles, errors={errors}"
    assert len(errors) == 1 and "reality" in errors[0].lower(), errors
    assert [p["config"]["protocol"] for p in profiles] == [
        "SHADOWSOCKS", "VLESS", "TROJAN", "VMESS"]
    # 2. Catalog filter on the sample: 4 unique -> 4, ids public-0..3.
    catalog = apply_free_server_catalog(profiles)
    assert [p["id"] for p in catalog] == ["public-0", "public-1", "public-2", "public-3"]
    checks["catalog_take"] = len(catalog)
    # 3. Share seal/open round-trip (password path).
    cfg = profiles[1]["config"]
    env = seal_share(cfg, "test-password-123", expires_at=int(time.time() * 1000) + 3600000)
    opened, meta = open_share(env, "test-password-123")
    assert opened["server"] == cfg["server"] and opened["uuid"] == cfg["uuid"]
    checks["share_round_trip"] = "OK"
    try:
        open_share(env, "wrong-password")
        raise AssertionError("wrong password opened the share")
    except DecodeError as exc:
        assert exc.code == "WRONG_PASSWORD"
    checks["share_wrong_password"] = "rejected"
    # 4. DarkTunnel node form round-trip through parse_one.
    node = {"name": "DT", "type": "VLESS",
            "vlessTunnelConfig": {
                "v2rayConfig": {"host": "dt.example.com", "port": 443,
                                "uuid": "44444444-4444-4444-8444-444444444444",
                                "serverNameIndication": "dt.example.com",
                                "transportNetwork": "Websocket",
                                "wsPath": "/dt", "wsHeaderHost": "dt.example.com"},
                "injectConfig": {"enabled": False, "proxyHost": "",
                                 "payload": ""}}}
    dt_link = "darktunnel://" + base64.b64encode(
        json.dumps(node).encode()).decode()
    dt_profiles, dt_errors = parse_text(dt_link)
    assert len(dt_profiles) == 1 and not dt_errors, dt_errors
    assert dt_profiles[0]["config"]["server"] == "dt.example.com"
    checks["darktunnel"] = "OK"
    # 5. Redaction: no IPv4 survives.
    red, left = redact({"profiles": catalog})
    assert left == 0, f"redaction left {left} IPs"
    assert all(p["config"]["uuid"] == "" for p in red["profiles"])
    checks["redaction_ips_left"] = left
    print(json.dumps({"self_test": "OK", **checks}, ensure_ascii=False))
    return 0


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    source = parser.add_mutually_exclusive_group(required=False)
    source.add_argument("file", nargs="?", type=Path,
                        help="Archivo con enlaces / JSON / Base64 (también acepta un share DGMTUNNEL_SHARE)")
    source.add_argument("--url", nargs="?", const=FEED_URL,
                        help="Descarga explícita del feed (por defecto, el feed de la app)")
    source.add_argument("--stdin", action="store_true",
                        help="Leer la entrada desde stdin")
    parser.add_argument("-o", "--output", type=Path,
                        help="Guardar el JSON; por defecto stdout")
    parser.add_argument("--catalog", action="store_true",
                        help="Aplicar el filtro de FreeServerCatalog (40 primeros) a un archivo local")
    parser.add_argument("--all", action="store_true",
                        help="Con --url: no aplicar el filtro de catálogo, devolver los 500 perfiles parseados")
    parser.add_argument("--limit", type=int, default=PARSE_LIMIT,
                        help="Límite de perfiles parseados (app: 500)")
    parser.add_argument("--share-password", default=None,
                        help="Contraseña para abrir un share DGMTUNNEL_SHARE protegido "
                             "(si se omite y el share la pide, se pregunta por teclado)")
    parser.add_argument("--redact", action="store_true",
                        help="Salida redactada: IPv4 -> REDACTED, uuid/password vacíos, sin source_uri")
    parser.add_argument("--self-test", action="store_true",
                        help="Pruebas sintéticas sin red: parseo, catálogo, share y redacción")
    args = parser.parse_args(argv)
    try:
        if args.self_test:
            return _self_test()
        fetched_at = None
        if args.url is not None:
            raw = fetch_feed(args.url)
            fetched_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
            text = raw.decode("utf-8")
            feed_lines = len(text.splitlines())
            feed_entries = len([l for l in text.splitlines()
                                if l.strip() and not l.strip().startswith("#")])
            profiles, errors = parse_text(text, limit=args.limit)
            catalog_mode = not args.all
        elif args.stdin:
            raw = sys.stdin.buffer.read(MAX_BYTES + 1)
            text = raw.decode("utf-8")
            if len(raw) > MAX_BYTES:
                raise DecodeError("SIZE_LIMIT", "La entrada supera el límite de tamaño.")
            profiles, errors = _open_maybe_share(text, args)
            catalog_mode = args.catalog
            feed_lines = feed_entries = None
        elif args.file is not None:
            data = args.file.read_bytes()
            if len(data) > MAX_BYTES:
                raise DecodeError("SIZE_LIMIT", "El archivo supera el límite de tamaño.")
            text = data.decode("utf-8")
            profiles, errors = _open_maybe_share(text, args)
            catalog_mode = args.catalog
            feed_lines = feed_entries = None
        else:
            parser.error("se requiere un archivo, --url o --stdin (o --self-test)")
        for p in profiles:
            if "source_uri" not in p:
                p["source_uri"] = ""
        if catalog_mode:
            final_profiles = apply_free_server_catalog(profiles)
            # keep the source link of each kept profile for the complete copy
            src_by_key = {}
            for p in profiles:
                c = p["config"]
                src_by_key.setdefault(
                    (c["protocol"], c["server"], c["port"], c["uuid"]),
                    p.get("source_uri", ""))
            for p in final_profiles:
                c = p["config"]
                p["source_uri"] = src_by_key.get(
                    (c["protocol"], c["server"], c["port"], c["uuid"]), "")
            doc = {"app": "DGM Tunnel", "package": APP_PACKAGE,
                   "versionName": APP_VERSION_NAME, "versionCode": APP_VERSION_CODE,
                   "source": SOURCE_NAME, "fetched_at": fetched_at,
                   "feed_lines": feed_lines, "feed_entries": feed_entries,
                   "parsed_profiles": len(profiles),
                   "rejected_entries": len(errors),
                   "rejected_reasons": _count_reasons(errors),
                   "profiles": final_profiles}
        else:
            doc = {"app": "DGM Tunnel", "package": APP_PACKAGE,
                   "versionName": APP_VERSION_NAME, "versionCode": APP_VERSION_CODE,
                   "profiles": profiles, "errors": errors}
        _validate_json(doc)
        if args.redact:
            doc, ips_left = redact(doc)
            print(json.dumps({"redacted_ips_left": ips_left}, ensure_ascii=False),
                  file=sys.stderr)
        rendered = json.dumps(doc, ensure_ascii=False, indent=2, allow_nan=False) + "\n"
        if args.output:
            args.output.write_text(rendered, encoding="utf-8")
        else:
            sys.stdout.write(rendered)
        print(json.dumps({"profiles": len(doc.get("profiles", [])),
                          "parsed": len(profiles), "errors": len(errors),
                          "fetched_at": fetched_at}, ensure_ascii=False),
              file=sys.stderr)
        return 0
    except DecodeError as exc:
        print(json.dumps({"error": exc.code, "message": str(exc)}, ensure_ascii=False),
              file=sys.stderr)
        return 1
    except OSError:
        print(json.dumps({"error": "IO_ERROR",
                          "message": "No se pudo leer o escribir el archivo."}),
              file=sys.stderr)
        return 2


def _count_reasons(errors):
    from collections import Counter
    reasons = Counter()
    for e in errors:
        msg = e.split(" : ", 1)[1] if " : " in e else e
        reasons[msg] += 1
    return dict(reasons)


def _share_envelope_text(text: str):
    """Return the DGMTUNNEL_SHARE envelope JSON for a share in any of the
    forms ShareCodec.unwrap accepts (dgmtunnel://share/<b64url>, raw JSON,
    bare Base64 of the JSON), or None if the text is not a share envelope."""
    stripped = text.strip()
    candidates = []
    if stripped.lower().startswith("dgmtunnel://share/"):
        candidates.append(stripped.split("/share/", 1)[1].strip())
    elif stripped.startswith("{"):
        candidates.append(stripped)
    else:
        candidates.append(stripped)
    for candidate in candidates:
        try:
            decoded = _b64decode_text(candidate)
        except Exception:
            decoded = candidate
        if decoded.strip().startswith("{") and '"DGMTUNNEL_SHARE"' in decoded:
            try:
                if json.loads(decoded).get("format") == SHARE_FORMAT:
                    return decoded
            except ValueError:
                pass
    return None


def _open_maybe_share(text: str, args):
    """File/stdin entry: a DGMTUNNEL_SHARE envelope opens as one profile,
    anything else goes through ConfigImporter.parse. Attaches source_uri."""
    envelope_text = _share_envelope_text(text)
    if envelope_text is not None:
        password = args.share_password
        if password is None:
            # Only prompt when the envelope is actually password-protected,
            # so password-less shares also work non-interactively.
            try:
                protected = bool(json.loads(envelope_text).get("passwordProtected"))
            except ValueError:
                protected = True
            if protected:
                try:
                    password = getpass.getpass("Contraseña del share: ")
                except (EOFError, KeyboardInterrupt):
                    password = None
        cfg, meta = open_share(text.strip(), password)
        profile = _profile(cfg)
        profile["share"] = meta
        return [profile], []
    profiles, errors = parse_text(text, limit=args.limit)
    return profiles, errors


if __name__ == "__main__":
    raise SystemExit(main())

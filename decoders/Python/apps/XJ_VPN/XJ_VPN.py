#!/usr/bin/env python3
"""XJ VPN 1.9.7 (net.xj.vpn): catalog decoder, local or explicit HTTPS.

Standalone Python 3.10+, standard library only; no APK needed at runtime.
See README.md here.

Method (verified against this APK, versionCode 99, versionName 1.9.7;
the SP-DECODE repo has NO provider for XJ VPN as of 2026-11-14 --
only CATNET_VPN in decoders/Python/apps/CATNET_VPN/manifest.json,
which is a different app on the same backend family):

  BASE_URL https://onlinetoolx.com/xjvpn/  (ApiClient <clinit>, resolved
  from the obfuscated runtime/d.b(33); the literal string is in the DEX)
  APP_KEY  "xj_vpn"   APP_PACKAGE "net.xj.vpn"   version code 99
  (ApiClient fields; APP_KEY resolved from runtime/d.b(33), an
  AES-GCM double-decrypt whose keys come from hex in <clinit>)

  Preflight (the app calls it first, MobileApiService.appUpdate):
  GET mobile/public/app-update?app_key=xj_vpn&current_version_code=99
  -> HTTP 200, ApiResponse {success, data}. Live 2026-11-14:
     maintenance false, update_available false,
     integrity_required true, integrity_challenge = JWT
     {app: xj_vpn, pkg: net.xj.vpn, ver: 99, nonce, exp} (fresh on
     every call: new installation id + nonce each time).
     NOTE: the preflight also claims latest_version_code 66 / 1.6.2,
     stale server data (the app itself is 1.9.7/99).

  Catalog endpoints (MobileApiService, Retrofit @GET, no body):
    mobile/public/servers
    mobile/public/payloads
    mobile/public/xray_payloads
    mobile/public/v2ray-configs
    mobile/public/accounts
  All five are requested with the exact OkHttp interceptor headers
  (ApiClient$special$$inlined$-addInterceptor$1):
    X-XJ-App-Key / X-App-Key: xj_vpn
    X-XJ-App-Package / X-App-Package / X-Package-Name /
      X-XJ-Package-Name: net.xj.vpn
    X-XJ-Installation-Id: <installation uuid>
    X-XJ-Version-Code: 99
    X-XJ-Integrity-Session / X-XJ-Integrity-Token /
      X-XJ-Integrity-Challenge / X-XJ-Request-Hash: only when the app
      holds them (after a successful Play Integrity handshake)
    User-Agent: okhttp/4.12.0 (OkHttp default; the interceptor sets
      no User-Agent of its own)

  Live test (2026-11-14, --url, this script): the preflight answers
  200, but EVERY catalog endpoint answers the identical
  HTTP 403, 242 bytes:
    {"success":false,"modified_app":true,"integrity_rejected":false,
     "message":"This app installation is not verified. Install the
     official XJ app from Google Play.",
     "play_store_url":"https://play.google.com/store/apps/details?id=net.xj.vpn"}
  The server demands a valid Play Integrity verdict (a token only
  Google Play Integrity can issue on a real device running the
  genuine Play-installed app). No offline script can produce it, so
  the live catalog is honestly reported as LIVE_BLOCKED_BY_INTEGRITY,
  not invented. This is the same gate CATNET 1.2.7 hit in batch 6
  (its catalog was also blocked), except CATNET's gate let the
  servers endpoint through in 1.2.7; XJ 1.9.7 blocks all five.

  What a real device would do next (for the record, not replicable
  offline): the app takes the preflight integrity_challenge JWT,
  requests a Play Integrity token, exchanges it with the server
  (the obfuscated api/n.../ endpoints), stores integritySession /
  integrityToken, and retries the catalog calls with the
  X-XJ-Integrity-* headers. A live capture on a Play-installed
  device (or a real exported .xj / xjdev:// link from the app)
  is the only way to see the real catalog.

File formats: .xj files and the xj://, xjdev:// (v2) / xjvpn://
(v1 legacy) and xjgcp:// text links are decoded by
XJ_VPN_archivos.py. The app declares those four schemes plus the
.xj VIEW intent-filter (mime application/x-xjvpn, pathPattern .*\\.xj).
"""
from __future__ import annotations

import argparse
import json
import math
import sys
import uuid
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

MAX_BYTES = 5 * 1024 * 1024
MAX_DEPTH = 64
MAX_NODES = 1_000_000

BASE_URL = "https://onlinetoolx.com/xjvpn/"
APP_KEY = "xj_vpn"
APP_PACKAGE = "net.xj.vpn"
VERSION_CODE = 99
USER_AGENT = "okhttp/4.12.0"

PREFLIGHT_PATH = "mobile/public/app-update?app_key=xj_vpn&current_version_code=99"
CATALOG_PATHS = (
    "mobile/public/servers",
    "mobile/public/payloads",
    "mobile/public/xray_payloads",
    "mobile/public/v2ray-configs",
    "mobile/public/accounts",
)

# Real 403 body returned by every catalog endpoint on 2026-11-14
# (identical for all five). Used by --self-test as the blocked-path
# test vector; the live call re-verifies it instead of trusting this.
BLOCKED_BODY = (
    b'{"success":false,"modified_app":true,"integrity_rejected":false,'
    b'"message":"This app installation is not verified. Install the '
    b'official XJ app from Google Play.",'
    b'"play_store_url":"https://play.google.com/store/apps/details?id=net.xj.vpn"}'
)


class DecodeError(ValueError):
    """Error de descifrado con un código estable para SP-DECODE."""

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


def _unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate key")
        result[key] = value
    return result


def _nonfinite(_value):
    raise ValueError("nonfinite number")


def _validate(doc):
    pending, count = [(doc, 0)], 0
    while pending:
        value, depth = pending.pop()
        count += 1
        if depth > MAX_DEPTH or count > MAX_NODES:
            raise DecodeError("SIZE_LIMIT", "El JSON supera el límite de complejidad.")
        if isinstance(value, dict):
            pending.extend((v, depth + 1) for v in value.values())
            pending.extend((k, depth + 1) for k in value)
        elif isinstance(value, list):
            pending.extend((v, depth + 1) for v in value)
        elif isinstance(value, float) and not math.isfinite(value):
            raise ValueError("nonfinite number")
    return doc


def _json(data):
    try:
        doc = json.loads(data, object_pairs_hook=_unique, parse_constant=_nonfinite)
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise DecodeError("INVALID_JSON", f"JSON inválido: {exc}") from exc
    return _validate(doc)


def _headers(installation_id: str | None = None):
    """Exact OkHttp interceptor headers (no integrity session: the
    script has none, exactly like a fresh install before the
    handshake)."""
    return {
        "X-XJ-App-Key": APP_KEY,
        "X-App-Key": APP_KEY,
        "X-XJ-App-Package": APP_PACKAGE,
        "X-App-Package": APP_PACKAGE,
        "X-Package-Name": APP_PACKAGE,
        "X-XJ-Package-Name": APP_PACKAGE,
        "X-XJ-Version-Code": str(VERSION_CODE),
        "X-XJ-Installation-Id": installation_id or str(uuid.uuid4()),
        "User-Agent": USER_AGENT,
        "Accept-Encoding": "identity",
    }


def _fetch(path: str, timeout: int = 30):
    """One GET exactly as the app issues it. Returns (status, body)."""
    url = BASE_URL + path if not path.startswith("http") else path
    req = Request(url, headers=_headers(), method="GET")
    try:
        with urlopen(req, timeout=timeout) as resp:
            body = resp.read(MAX_BYTES + 1)
            if len(body) > MAX_BYTES:
                raise DecodeError("SIZE_LIMIT", "Respuesta mayor que el límite.")
            return resp.status, body
    except HTTPError as exc:
        body = exc.read(MAX_BYTES + 1)
        return exc.code, body
    except URLError as exc:
        raise DecodeError("NETWORK", f"Error de red: {exc}") from exc


def decode(data) -> dict:
    """Decode one catalog response body (bytes) into a summary dict.

    Success shape: {"success": true, "data": {...}} with the servers /
    payloads list inside "data" (list, or dict holding the list under
    "servers"/"payloads"/"items"). The exact success shape could not
    be observed live (the server blocks before returning data), so
    decode() accepts any of those placements and reports the counts
    it finds. A modified_app 403 raises LIVE_BLOCKED_BY_INTEGRITY.
    """
    if isinstance(data, str):
        data = data.encode("utf-8")
    if len(data) > MAX_BYTES:
        raise DecodeError("SIZE_LIMIT", "Respuesta mayor que el límite.")
    doc = _json(data)
    if not isinstance(doc, dict):
        raise DecodeError("INVALID_JSON", "La respuesta no es un objeto JSON.")
    if doc.get("modified_app") is True or doc.get("success") is False and doc.get("modified_app"):
        raise DecodeError(
            "LIVE_BLOCKED_BY_INTEGRITY",
            "El servidor rechazó la petición (HTTP 403, modified_app=true): "
            "exige un veredicto válido de Play Integrity, que solo puede "
            "emitir Google Play Integrity en un dispositivo real con la app "
            "genuina instalada desde Play. Sin ese token no hay catálogo.",
        )
    if doc.get("success") is False:
        raise DecodeError(
            "SERVER_ERROR",
            f"El servidor respondió success=false: {json.dumps(doc, ensure_ascii=False)[:300]}",
        )
    payload = doc.get("data", doc)
    servers = payloads = None
    if isinstance(payload, list):
        servers = payload
    elif isinstance(payload, dict):
        for key in ("servers", "payloads", "items", "configs", "v2rayConfigs"):
            if isinstance(payload.get(key), list):
                if key == "servers":
                    servers = payload[key]
                elif key == "payloads":
                    payloads = payload[key]
        if servers is None and payloads is None:
            # A data dict with no list: keep it as-is (e.g. preflight).
            return {"kind": "response", "data": payload}
    free = 0
    if servers is not None:
        free = sum(1 for s in servers
                   if isinstance(s, dict) and str(s.get("status", "")).lower() in ("", "active", "online", "free", "1", "true"))
    return {
        "kind": "catalog",
        "servers_total": len(servers) if servers is not None else 0,
        "servers_free": free,
        "payloads_total": len(payloads) if payloads is not None else 0,
        "servers": servers or [],
        "payloads": payloads or [],
    }


def run(file_bytes) -> str | None:
    """SP-DECODE entry point: raw catalog bytes -> JSON string or None."""
    try:
        return json.dumps(decode(file_bytes), ensure_ascii=False)
    except DecodeError:
        return None


def fetch_catalog(timeout: int = 30) -> dict:
    """Preflight + all catalog endpoints, exactly as the app does.
    Returns a report dict; raises DecodeError LIVE_BLOCKED_BY_INTEGRITY
    when every catalog endpoint is integrity-blocked (the expected
    result until a real device token exists)."""
    report: dict = {"base_url": BASE_URL, "app_key": APP_KEY,
                    "package": APP_PACKAGE, "version_code": VERSION_CODE,
                    "preflight": None, "endpoints": {}}
    status, body = _fetch(PREFLIGHT_PATH, timeout=timeout)
    preflight_status = status
    try:
        pre = _json(body)
    except DecodeError:
        pre = {"raw": body[:400].decode("utf-8", "replace")}
    report["preflight"] = {"http": status, "body": pre}
    blocked = 0
    for path in CATALOG_PATHS:
        status, body = _fetch(path, timeout=timeout)
        entry = {"http": status, "bytes": len(body),
                 "body": body[:400].decode("utf-8", "replace")}
        try:
            summary = decode(body)
            entry["summary"] = {k: v for k, v in summary.items()
                                if k in ("servers_total", "servers_free", "payloads_total")}
        except DecodeError as exc:
            entry["error"] = exc.code
            if exc.code == "LIVE_BLOCKED_BY_INTEGRITY":
                blocked += 1
        report["endpoints"][path] = entry
    if blocked == len(CATALOG_PATHS):
        raise DecodeError(
            "LIVE_BLOCKED_BY_INTEGRITY",
            f"Preflight HTTP {preflight_status} OK (integrity_required=true), pero los "
            f"{len(CATALOG_PATHS)} endpoints del catálogo devolvieron HTTP 403 "
            "modified_app=true. El catálogo en vivo está bloqueado por Play "
            "Integrity; hace falta un token válido de un dispositivo real.",
        )
    return report


def _self_test():
    # 1. The recorded real 403 body must raise the blocked code.
    try:
        decode(BLOCKED_BODY)
    except DecodeError as exc:
        assert exc.code == "LIVE_BLOCKED_BY_INTEGRITY", exc.code
    else:
        raise AssertionError("el cuerpo 403 no lanzó LIVE_BLOCKED_BY_INTEGRITY")
    # 2. A synthetic success body (field names from ServerDto /
    # PublicPayloadDto; NOT a real catalog) must parse and count.
    sample = json.dumps({
        "success": True,
        "data": {
            "servers": [
                {"servername": "Servidor de prueba 1", "ip": "203.0.113.10",
                 "status": "active", "country": "Mexico",
                 "server_protocol": "SSH", "uuid": "00000000-0000-0000-0000-000000000001"},
                {"servername": "Servidor de prueba 2", "ip": "203.0.113.11",
                 "status": "offline", "country": "Brasil",
                 "server_protocol": "V2Ray", "uuid": "00000000-0000-0000-0000-000000000002"},
            ],
            "payloads": [
                {"payload_name": "Payload de prueba", "payload_mode": "SSH",
                 "payload_protocol": "SSH", "payload_id": 1},
            ],
        },
    }).encode("utf-8")
    out = decode(sample)
    assert out["servers_total"] == 2 and out["servers_free"] == 1, out
    assert out["payloads_total"] == 1, out
    assert run(sample) is not None and run(BLOCKED_BODY) is None
    # 3. Headers must be exactly the interceptor set.
    hdrs = _headers(installation_id="00000000-0000-0000-0000-000000000000")
    assert hdrs["X-XJ-App-Key"] == "xj_vpn" and hdrs["X-App-Key"] == "xj_vpn"
    assert hdrs["X-XJ-App-Package"] == "net.xj.vpn"
    assert hdrs["X-Package-Name"] == "net.xj.vpn"
    assert hdrs["X-XJ-Version-Code"] == "99"
    assert hdrs["User-Agent"] == "okhttp/4.12.0"
    print("self-test OK: 403 bloqueado -> LIVE_BLOCKED_BY_INTEGRITY; "
          "parseo sintético 2 servidores (1 gratis) + 1 payload; "
          "cabeceras exactas de la app")


def main(argv=None):
    parser = argparse.ArgumentParser(description="XJ VPN 1.9.7: catálogo en vivo (onlinetoolx.com/xjvpn).")
    parser.add_argument("--url", nargs="?", const="", default=None,
                        help="Probar en vivo: sin valor descarga preflight + los 5 endpoints; "
                             "con una URL/path descarga solo ese recurso.")
    parser.add_argument("--self-test", action="store_true",
                        help="Pruebas locales sin red.")
    args = parser.parse_args(argv)
    if args.self_test:
        _self_test()
        return 0
    if args.url is None:
        parser.print_help()
        return 2
    if args.url == "":
        try:
            report = fetch_catalog()
        except DecodeError as exc:
            print(f"RESULTADO: {exc.code}\n{exc}")
            pre_status, pre_body = _fetch(PREFLIGHT_PATH)
            print(f"Preflight: HTTP {pre_status} "
                  f"(integrity_required={_json(pre_body).get('data', {}).get('integrity_required')})")
            return 1
        print(json.dumps(report, ensure_ascii=False, indent=2))
        return 0
    path = args.url
    status, body = _fetch(path)
    print(f"HTTP {status}, {len(body)} B")
    try:
        summary = decode(body)
        print(json.dumps(summary, ensure_ascii=False, indent=2)[:4000])
    except DecodeError as exc:
        print(f"RESULTADO: {exc.code}\n{exc}")
        print(body[:400].decode("utf-8", "replace"))
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())

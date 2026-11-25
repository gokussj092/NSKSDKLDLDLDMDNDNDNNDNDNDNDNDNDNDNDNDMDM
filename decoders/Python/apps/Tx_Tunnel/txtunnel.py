#!/usr/bin/env python3
"""Tx Tunnel v1.10.11.3 (72) — decodificador de archivos, textos y catalogo vivo.

Paquete ``co.strongteam.ospro``; v2rayNG fork + Sandok/UltraSSH. El
catalogo y los campos van cifrados con un sobre propio (NO es perfil
RENZ: los 16 perfiles de ``decoders/Python/renz.py`` no abren
``assets/configfile.json``).

Metodo (recuperado del Go de ``libgojni.so`` — ``AndroidLibXrayLite`` —
y verificado en vivo 2026-11-25):

  sobre: Base64 Std -> salt[0:16] || nonce[16:28] || ct+tag[28:]
  clave: Argon2id(password, salt, time=3, memory=16384 KiB, threads=1,
         keyLen=32); AES-256-GCM(key, nonce, AAD=salt)
  DOS contrasenas distintas segun el canal:
    * P17 ``TXTunnel2026@Pass`` — DO/EO: catalogo incluido (assets),
      cache MMKV, campos individuales del catalogo y archivos
      .txtunnel importados por la ruta B (``Hometab$Companion.a``).
    * P32 ``l69OTFpdXM1vsTE6jeMVcw5uq9A5iNWg`` — decrypt/Encrypt:
      catalogo vivo (``CU``) y archivos .txtunnel exportados
      (``NetworkAdapter.u`` -> ``Libv2ray.encrypt``; importados por
      ``ConfigFileParser`` ruta A -> ``Libv2ray.parseConfig``).

Catalogo vivo: POST a https://strongteam.co/api/txtunnelnew/
  body ``hash=xsandokUpdatex`` (application/x-www-form-urlencoded),
  sin mas headers. Respuesta: un sobre P32 con el JSON del catalogo.
  ``CU`` compara su ``Version`` con la actual y solo actualiza si la
  remota es mayor. Verificado en vivo 2026-11-25: Version 66.87
  (incluido 2.0), 30 servidores, 651 networks (payloads). Nota: la
  respuesta viene chunked detras de Cloudflare y el lector de urllib
  la trunca en este entorno; el script usa requests, luego urllib y
  luego curl, y el GCM valida que el cuerpo este completo.

Archivos .txtunnel (``com.v2ray.ang.ui.ConfigFileParser``, max 2 MB):
  JSON de un network cifrado con P32 (export) — tambien se acepta
  P17 o JSON plano. La importacion exige ``Name`` y ``TunnelType``.
  Sin muestra real todavia: VERIFIED_SYNTHETIC (round-trip).

Textos v2rayng:// (hosts install-config / install-sub): el parseo de
vmess/vless/trojan/ss/hy2 es el estandar de v2rayNG; tambien
VERIFIED_SYNTHETIC (sin muestra real).

El catalogo COMPLETO lleva credenciales de servidor (IP, usuario,
contrasena, UUID V2Ray, payloads). Va SOLO a
``~/workspace/batch-nov25/txtunnel/catalog-completo.json``, NUNCA en
el ZIP ni en Drive. Para el ZIP/Drive usar la copia redactada
(``--fetch --redacted``). El JSON de resultado solo lleva los datos
descifrados; no incluye las APIs de descarga del catalogo, y no hay
creditos dentro del script ni de sus resultados.

CORRECCION 2026-11-25 (auditoria de campos, app 5 de 6): el
descifrado de campos es ahora GENERICO — recorre TODO el catalogo
(nivel superior + Servers + Networks) y descifra cualquier valor
con forma de sobre (P17 primero, P32 como respaldo), en vez de
limitarse a una lista cerrada de campos. Tras descifrar, ``--fetch
--full-fields`` ejecuta ``audit_decrypted_catalog`` y exige 0
valores con pinta de cifrado restantes. OJO: un valor hex puro
(``SlowDNSKey`` de 64 caracteres, ``OVPNUser``/``OVPNPass`` de 32)
NO es un sobre sin descifrar: es el valor real tal cual, verificado
en el APK (``HomeFragment.n0`` copia ``getSlowDNSKey()`` verbatim a
``F0`` y ``H0``/``J0`` lo guardan verbatim en preferencias; el
catálogo incluido v2.0 trae la misma clave hex). Los certificados
OVPN en claro y los enlaces ``vmess://``/``vless://`` en
``V2rayConfig`` son tambien valores, no cifrado (ver ANALISIS §6.1).

Uso::

    python txtunnel.py --fetch [--out catalog.json] [--redacted] [--full-fields]
    python txtunnel.py configfile.json [--out catalog.json] [--redacted]
    python txtunnel.py red.txtunnel [--out network.json]
    python txtunnel.py --text 'v2rayng://install-config?url=vmess://...'
    python txtunnel.py --text 'vmess://...' [--out config.json]
    python txtunnel.py --stdin < red.txtunnel
    python txtunnel.py --self-test

Dependencias: argon2-cffi y pycryptodome
(``~/workspace/http-custom-update/venv`` las tiene).

Estado: catalogo VERIFIED_REAL (incluido + vivo, descifrados y
verificados 2026-11-25). Campos individuales VERIFIED_REAL.
Archivos .txtunnel y textos v2rayng:// VERIFIED_SYNTHETIC.
"""
from __future__ import annotations

import argparse
import base64
import binascii
import json
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

try:
    from argon2.low_level import Type as _Argon2Type
    from argon2.low_level import hash_secret_raw as _argon2_raw
except ImportError as exc:  # pragma: no cover
    raise SystemExit(
        "Falta argon2-cffi (pip install argon2-cffi). "
        "El venv ~/workspace/http-custom-update/venv ya la tiene."
    ) from exc

try:
    from Crypto.Cipher import AES
except ImportError as exc:  # pragma: no cover
    raise SystemExit(
        "Falta pycryptodome (pip install pycryptodome). "
        "El venv ~/workspace/http-custom-update/venv ya lo tiene."
    ) from exc

# ---------------------------------------------------------------------------
# Cripto del sobre (ver ANALISIS.md: DO/EO vs decrypt/Encrypt en libgojni.so)
# ---------------------------------------------------------------------------

PASSWORD_LOCAL = b"TXTunnel2026@Pass"            # P17: DO / EO
PASSWORD_LIVE = b"l69OTFpdXM1vsTE6jeMVcw5uq9A5iNWg"  # P32: decrypt / Encrypt

ARGON2_TIME = 3
ARGON2_MEMORY_KIB = 16384
ARGON2_THREADS = 1
ARGON2_KEY_LEN = 32

LIVE_URL = "https://strongteam.co/api/txtunnelnew/"
LIVE_BODY = b"hash=xsandokUpdatex"
LIVE_HEADERS = {
    "Content-Type": "application/x-www-form-urlencoded",
    "User-Agent": "Go-http-client/1.1",  # UA por defecto del cliente Go
}
MAX_FILE_BYTES = 2 * 1024 * 1024  # limite de ConfigFileParser (2 MB)


def _derive_key(password: bytes, salt: bytes) -> bytes:
    return _argon2_raw(
        password,
        salt,
        time_cost=ARGON2_TIME,
        memory_cost=ARGON2_MEMORY_KIB,
        parallelism=ARGON2_THREADS,
        hash_len=ARGON2_KEY_LEN,
        type=_Argon2Type.ID,
    )


def decrypt_envelope(blob_b64: str, password: bytes) -> bytes:
    """Descifra un sobre Base64 (salt||nonce||ct+tag, AAD=salt)."""
    try:
        raw = base64.b64decode(blob_b64.strip(), validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ValueError("no es Base64 valido") from exc
    if len(raw) < 28:
        raise ValueError(f"sobre demasiado corto ({len(raw)} bytes < 28)")
    salt, nonce, ct = raw[:16], raw[16:28], raw[28:]
    key = _derive_key(password, salt)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    cipher.update(salt)
    try:
        return cipher.decrypt_and_verify(ct[:-16], ct[-16:])
    except ValueError as exc:
        raise ValueError("GCM MAC check failed (contrasena o datos mal)") from exc


def encrypt_envelope(plaintext: bytes, password: bytes) -> str:
    """Cifra al sobre Base64 (salt y nonce aleatorios, AAD=salt)."""
    import os

    salt = os.urandom(16)
    nonce = os.urandom(12)
    key = _derive_key(password, salt)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    cipher.update(salt)
    ct, tag = cipher.encrypt_and_digest(plaintext)
    return base64.b64encode(salt + nonce + ct + tag).decode("ascii")


# Par DO / EO (contrasena local P17)
def decrypt_do(blob_b64: str) -> bytes:
    return decrypt_envelope(blob_b64, PASSWORD_LOCAL)


def encrypt_eo(plaintext: bytes) -> str:
    return encrypt_envelope(plaintext, PASSWORD_LOCAL)


# Par decrypt / Encrypt (contrasena viva P32)
def decrypt_live(blob_b64: str) -> bytes:
    return decrypt_envelope(blob_b64, PASSWORD_LIVE)


def encrypt_live(plaintext: bytes) -> str:
    return encrypt_envelope(plaintext, PASSWORD_LIVE)


def decrypt_catalog_envelope(blob_b64: str) -> tuple[bytes, str]:
    """Descifra el sobre del catalogo: prueba P17 (incluido) y P32 (vivo)."""
    for password, name in ((PASSWORD_LOCAL, "P17-local"), (PASSWORD_LIVE, "P32-live")):
        try:
            return decrypt_envelope(blob_b64, password), name
        except ValueError:
            continue
    raise ValueError("el sobre del catalogo no abre con P17 ni con P32")


# ---------------------------------------------------------------------------
# Campos individuales del catalogo (todos P17; ver ANALISIS.md)
# ---------------------------------------------------------------------------

# Campos que en el catalogo son sobres P17 (el resto es plaintext/bool).
# Documentacion de los campos verificados como sobres; el descifrado
# generico (decrypt_catalog_fields) ya no depende de esta lista:
# recorre todo el catalogo y descifra cualquier valor con forma de
# sobre, asi un campo nuevo del servidor tambien queda cubierto.
SECRET_SERVER_FIELDS = (
    "ServerIPHost", "OVPNUser", "OVPNPass", "UDP_obfs", "UDP_user",
    "CustomCertificate", "SlowDNSHost", "SlowDNSKey", "V2rayUUID",
    "V2rayPath", "H2pass", "ServerInfo", "TrojanPass", "DynamicV2ray",
)
SECRET_NETWORK_FIELDS = (
    "Payload", "SNI", "CustomProxy", "V2rayConfig", "V2rayAddress",
    "V2rayHost", "V2raySNI", "VinJect", "Icon", "BugDNS",
)
# ...pero en la practica estos 5 son plaintext o bool, nunca sobres:
PLAINTEXT_FIELDS = {"CustomProxy", "Icon", "ServerInfo", "V2rayPath",
                    "DynamicV2ray", "VinJect"}

# Campos con credenciales/secretos: se redactan en la copia del ZIP/Drive.
REDACT_SERVER_FIELDS = (
    "ServerIPHost", "OVPNUser", "OVPNPass", "UDP_obfs", "UDP_user",
    "CustomCertificate", "SlowDNSHost", "SlowDNSKey", "V2rayUUID",
    "V2rayPath", "H2pass", "ServerInfo", "TrojanPass", "DynamicV2ray",
)
REDACT_NETWORK_FIELDS = (
    "Payload", "SNI", "CustomProxy", "V2rayConfig", "V2rayAddress",
    "V2rayHost", "V2raySNI", "VinJect", "Icon",
)
# BugDNS es mixto: casi siempre "8.8.8.8" en claro, pero 114 networks
# lo traen como sobre P17; en la copia redactada solo se redacta el
# sobre (el "8.8.8.8" en claro no es un secreto).
REDACT_IF_ENVELOPE_FIELDS = ("BugDNS",)
REDACT_TOP_FIELDS = (
    "DefOVPNUser", "DefOVPNPass", "HysteriaUser", "HysteriaOBFS",
    "DefaultOVPNCert",
)
REDACTED = "[REDACTED]"


def _looks_like_envelope(value) -> bool:
    if not isinstance(value, str) or not value:
        return False
    if _is_hex_value(value):
        # Un valor hex puro (p. ej. SlowDNSKey de 64 caracteres) es el
        # valor real tal cual, no un sobre: sus caracteres son un
        # subconjunto del alfabeto Base64 y decodificaria a >=28 bytes,
        # pero no es Base64 del sobre. Ver ANALISIS §6.1.
        return False
    try:
        raw = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError):
        return False
    return len(raw) >= 28


def _is_hex_value(value) -> bool:
    """True si el valor es hex puro de longitud par >= 32 (una clave
    o credencial en hex que la app usa tal cual: SlowDNSKey 64,
    OVPNUser/OVPNPass 32). No es un sobre cifrado."""
    if not isinstance(value, str) or len(value) < 32 or len(value) % 2:
        return False
    try:
        bytes.fromhex(value)
    except ValueError:
        return False
    return True


def _try_decrypt_field(value: str) -> tuple[str | None, str | None]:
    """Intenta descifrar un campo-sobre (P17, luego P32).
    Devuelve (plaintext, password_usada) o (None, None) si no abre.
    Un sobre de 44 bytes en crudo (salt16+nonce12+tag16+ct0) es por
    construccion plaintext vacio: se devuelve "" con origen
    "empty44" sin gastar una derivacion Argon2."""
    if len(base64.b64decode(value)) == 44:
        return "", "empty44"
    for password, name in ((PASSWORD_LOCAL, "P17"), (PASSWORD_LIVE, "P32")):
        try:
            return decrypt_envelope(value, password).decode("utf-8", "replace"), name
        except ValueError:
            continue
    return None, None


def _decrypt_one_field(value: str) -> tuple[str | None, str | None]:
    """Worker a nivel de modulo para multiprocessing: (plaintext, origen)
    o (None, None) si no abre. Debe vivir a nivel de modulo para que
    multiprocessing pueda referenciarlo (precedente VLX,
    decode_fields(workers=4)). Con fork en Linux hereda las claves y
    el binding argon2-cffi del proceso padre."""
    return _try_decrypt_field(value)


def decrypt_field(value):
    """Descifra un campo del catalogo (P17, luego P32). Devuelve el
    valor tal cual si es plaintext/bool/vacio, si es un valor hex
    (la app lo usa tal cual) o si no es un sobre; nunca inventa."""
    if not isinstance(value, str) or not value:
        return value
    if not _looks_like_envelope(value):
        return value
    plaintext, _which = _try_decrypt_field(value)
    return plaintext if plaintext is not None else value


def decrypt_catalog_fields(catalog: dict, workers: int = 0) -> tuple[dict, dict]:
    """Descifra TODOS los campos-sobre del catalogo: recorrido
    generico de todo el JSON (nivel superior + Servers + Networks),
    no una lista cerrada de campos. Cada valor con forma de sobre
    se prueba con P17 y luego con P32; el tag GCM valida cada
    apertura. Devuelve (catalogo_descifrado, estadisticas).

    ``workers``: con >1, los sobres unicos se descifran en paralelo
    con multiprocessing.Pool (precedente VLX, decode_fields
    workers=4). El catálogo vivo tiene ~4.320 sobres (~3.280
    derivaciones Argon2id de ~49 ms): en secuencial son ~166 s, por
    encima del cap CATALOG_TIMEOUT_SECONDS=120 del worker; con
    workers=4 baja a ~45 s. Con workers<=1 el comportamiento es
    identico al secuencial anterior. La salida es la misma con
    cualquier workers: cada valor unico se descifra una sola vez y
    se aplica a todas sus ubicaciones; los stats se cuentan por
    ocurrencia, como antes."""
    stats = {"ok": 0, "ok_p17": 0, "ok_p32": 0, "empty44": 0,
             "kept": 0, "failed": 0}
    out = json.loads(json.dumps(catalog))  # copia profunda

    # Primera pasada: recolectar sobres con su ubicacion y contar
    # "kept" exactamente como el recorrido anterior (un string
    # no-sobre cuenta como kept; los valores no-string o vacios no
    # cuentan y se recorren igual).
    locations = []  # (contenedor, clave_o_indice, valor)

    def collect(node):
        if isinstance(node, dict):
            for key, value in node.items():
                if isinstance(value, str) and value:
                    if _looks_like_envelope(value):
                        locations.append((node, key, value))
                    else:
                        stats["kept"] += 1
                else:
                    collect(value)
        elif isinstance(node, list):
            for item in node:
                collect(item)

    collect(out)
    if not locations:
        return out, stats

    # Deduplicar por valor: el mismo sobre aparece en varias redes y
    # descifra al mismo plaintext (el tag GCM lo garantiza).
    order: list[str] = []
    seen: set[str] = set()
    for _node, _key, value in locations:
        if value not in seen:
            seen.add(value)
            order.append(value)
    if workers and workers > 1:
        from multiprocessing import Pool
        with Pool(processes=workers) as pool:
            results = pool.map(_decrypt_one_field, order)
    else:
        results = [_decrypt_one_field(value) for value in order]
    plain = dict(zip(order, results))

    # Segunda pasada: aplicar por ocurrencia, con los mismos stats.
    for node, key, value in locations:
        plaintext, which = plain[value]
        if plaintext is not None:
            node[key] = plaintext
            if which == "empty44":
                stats["empty44"] += 1
            else:
                stats["ok"] += 1
                stats["ok_p17" if which == "P17" else "ok_p32"] += 1
        else:
            stats["failed"] += 1
    return out, stats


def audit_decrypted_catalog(catalog: dict) -> dict:
    """Audita un catalogo ya descifrado, campo por campo.

    - ``remaining``: valores con forma de sobre Base64 (crudo >=28 B)
      que NO son hex puro: si la lista no esta vacia, queda cifrado
      real sin descifrar (o un campo con otro esquema).
    - ``hex_values``: valores hex puros (SlowDNSKey 64, OVPN 32):
      son el valor real tal cual, NO cifrado. Se cuentan por campo.
    - Los certificados OVPN (PEM en claro) y los enlaces
      vmess:// / vless:// en V2rayConfig son texto/enlaces en claro:
      su Base64 interior (DER del certificado, JSON del vmess) es
      codificacion del formato, no cifrado; no se cuentan aqui.
    Devuelve {"remaining": [...], "hex_values": {...}, "ok": bool}."""
    from collections import Counter

    remaining = []
    hex_values: Counter = Counter()

    def walk(node, path):
        if isinstance(node, dict):
            for key, value in node.items():
                walk(value, f"{path}.{key}")
        elif isinstance(node, list):
            for i, item in enumerate(node):
                walk(item, f"{path}[{i}]")
        elif isinstance(node, str) and node:
            if _is_hex_value(node):
                hex_values[path.split(".")[-1].split("[")[0]] += 1
            else:
                try:
                    raw = base64.b64decode(node, validate=True)
                except (binascii.Error, ValueError):
                    return
                if len(raw) >= 28:
                    remaining.append((path, node[:80]))

    walk(catalog, "$")
    return {
        "remaining": remaining,
        "hex_values": dict(hex_values),
        "ok": not remaining,
    }


def redact_catalog(catalog: dict) -> dict:
    """Copia del catalogo sin credenciales ni secretos (para ZIP/Drive)."""
    out = json.loads(json.dumps(catalog))
    for field in REDACT_TOP_FIELDS:
        if field in out:
            out[field] = REDACTED
    for server in out.get("Servers", []):
        for field in REDACT_SERVER_FIELDS:
            if field in server and server[field] not in ("", None):
                server[field] = REDACTED
    for network in out.get("Networks", []):
        for field in REDACT_NETWORK_FIELDS:
            if field in network and network[field] not in ("", None):
                network[field] = REDACTED
        for field in REDACT_IF_ENVELOPE_FIELDS:
            if field in network and _looks_like_envelope(network[field]):
                network[field] = REDACTED
    return out


def catalog_summary(catalog: dict) -> dict:
    from collections import Counter

    servers = catalog.get("Servers", [])
    networks = catalog.get("Networks", [])
    return {
        "Version": catalog.get("Version"),
        "ReleaseNotes": catalog.get("ReleaseNotes"),
        "servers": len(servers),
        "networks": len(networks),
        "ServerProtocol": dict(Counter(s.get("ServerProtocol") for s in servers)),
        "ServerType": dict(Counter(s.get("ServerType") for s in servers)),
        "TunnelType": dict(Counter(n.get("TunnelType") for n in networks)),
        "flags": dict(Counter(s.get("Flag") for s in servers)),
        "free_named_networks": sum(
            1 for n in networks if "FREE" in str(n.get("Name", "")).upper()
        ),
    }


# ---------------------------------------------------------------------------
# Catalogo vivo
# ---------------------------------------------------------------------------

def compare_versions(a: str, b: str) -> int:
    """-1 si a<b, 0 si a==b, 1 si a>b (comparacion numerica por puntos)."""
    def parts(v):
        out = []
        for piece in str(v).split("."):
            try:
                out.append(int(piece))
            except ValueError:
                out.append(0)
        return out
    pa, pb = parts(a), parts(b)
    for x, y in zip(pa, pb):
        if x != y:
            return 1 if x > y else -1
    if len(pa) != len(pb):
        return 1 if len(pa) > len(pb) else -1
    return 0


def _fetch_via_requests(timeout: int) -> bytes:
    import requests  # type: ignore

    resp = requests.post(
        LIVE_URL,
        data={"hash": "xsandokUpdatex"},
        headers=LIVE_HEADERS,
        timeout=timeout,
    )
    resp.raise_for_status()
    return resp.content


def _fetch_via_urllib(timeout: int) -> bytes:
    req = urllib.request.Request(
        LIVE_URL, data=LIVE_BODY, headers=LIVE_HEADERS, method="POST"
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        body = resp.read()
        expected = resp.headers.get("Content-Length")
        if expected is not None and len(body) != int(expected):
            raise urllib.error.ContentTooShortError(
                f"cuerpo incompleto: {len(body)} de {expected} bytes", body
            )
    return body


def _fetch_via_curl(timeout: int) -> bytes:
    import subprocess

    proc = subprocess.run(
        ["curl", "-sS", "-m", str(timeout), "-X", "POST", LIVE_URL,
         "-H", f"Content-Type: {LIVE_HEADERS['Content-Type']}",
         "-H", f"User-Agent: {LIVE_HEADERS['User-Agent']}",
         "--data", LIVE_BODY.decode("ascii")],
        capture_output=True, timeout=timeout + 10,
    )
    if proc.returncode != 0:
        raise RuntimeError(f"curl fallo ({proc.returncode}): "
                           f"{proc.stderr.decode('utf-8', 'replace')[:200]}")
    return proc.stdout


def fetch_live_catalog(retries: int = 3, timeout: int = 60) -> dict:
    """POST al endpoint vivo y descifra la respuesta (sobre P32).

    Replica exacto a CU (AndroidLibXrayLite): POST, body
    ``hash=xsandokUpdatex``, Content-Type
    application/x-www-form-urlencoded. La respuesta viene con
    ``Transfer-Encoding: chunked`` detras de Cloudflare y el lector
    chunked de urllib la trunca en este entorno (IncompleteRead),
    mientras que requests/curl la leen completa: se prueban los
    transportes en ese orden y el descifrado GCM valida que el cuerpo
    este completo. Reintenta cada transporte ``retries`` veces."""
    transports = []
    try:
        import requests  # noqa: F401
        transports.append(("requests", _fetch_via_requests))
    except ImportError:
        pass
    transports.append(("urllib", _fetch_via_urllib))
    transports.append(("curl", _fetch_via_curl))
    last_exc: Exception | None = None
    for name, fetch in transports:
        for attempt in range(1, retries + 1):
            try:
                body = fetch(timeout)
                text = body.decode("utf-8").strip()
                plaintext = decrypt_live(text)
                return json.loads(plaintext.decode("utf-8"))
            except Exception as exc:  # noqa: BLE001 - se prueba el
                # siguiente transporte/intento; el GCM valida integridad
                last_exc = exc
                print(f"  {name} intento {attempt}/{retries} fallido: {exc}",
                      file=sys.stderr)
    raise RuntimeError(f"no se pudo descargar el catalogo vivo: {last_exc}")


# ---------------------------------------------------------------------------
# Archivos .txtunnel y textos v2rayng://
# ---------------------------------------------------------------------------

def import_txtunnel_content(content: str) -> tuple[dict, str]:
    """Importa el contenido de un .txtunnel como hace ConfigFileParser.

    Ruta A (parseConfig): sobre P32 -> JSON. Ruta B (DO): sobre P17 ->
    JSON. Si es JSON plano, se acepta tal cual. Exige Name/TunnelType.
    Devuelve (network_dict, ruta_usada)."""
    if len(content.encode("utf-8")) > MAX_FILE_BYTES:
        raise ValueError("archivo mayor de 2 MB (limite de la app)")
    text = content.strip()
    if not text:
        raise ValueError("archivo vacio")
    errors = []
    for label, fn in (("A/parseConfig-P32", decrypt_live),
                      ("B/DO-P17", decrypt_do)):
        try:
            decoded = fn(text).decode("utf-8")
            data = json.loads(decoded)
            if not isinstance(data, dict) or "Name" not in data:
                raise ValueError("JSON sin 'Name'")
            return data, label
        except Exception as exc:  # noqa: BLE001 - se prueban ambas rutas
            errors.append(f"{label}: {exc}")
    try:
        data = json.loads(text)
        if not isinstance(data, dict) or "Name" not in data:
            raise ValueError("JSON sin 'Name'")
        return data, "plano-JSON"
    except Exception as exc:  # noqa: BLE001
        errors.append(f"plano-JSON: {exc}")
    raise ValueError("no se pudo importar: " + "; ".join(errors))


def export_txtunnel(network: dict) -> str:
    """Exporta un network a .txtunnel como NetworkAdapter.u: JSON -> P32."""
    payload = json.dumps(network, ensure_ascii=False, separators=(",", ":"))
    return encrypt_live(payload.encode("utf-8"))


def parse_v2rayng_link(text: str) -> dict:
    """Parsea v2rayng://install-config?url=<enlace> o un enlace directo
    vmess://, vless://, trojan://, ss://, hy2:// (estandar v2rayNG)."""
    text = text.strip()
    out = {"raw": text}
    if text.startswith("v2rayng://"):
        parsed = urllib.parse.urlparse(text)
        query = urllib.parse.parse_qs(parsed.query)
        url = query.get("url", [None])[0]
        if parsed.path.strip("/") == "install-sub" or "sub" in query:
            out["kind"] = "subscription"
            out["url"] = url or parsed.path
            return out
        if not url:
            raise ValueError("v2rayng:// sin parametro url")
        out["kind"] = "install-config"
        text = url
        out["url"] = url
    if text.startswith("vmess://"):
        b64 = text[len("vmess://"):]
        b64 += "=" * (-len(b64) % 4)
        data = json.loads(base64.urlsafe_b64decode(b64).decode("utf-8"))
        out.update({"kind": "vmess", "config": data})
        return out
    if text.startswith(("vless://", "trojan://", "ss://", "hy2://")):
        parsed = urllib.parse.urlparse(text)
        out.update({
            "kind": parsed.scheme,
            "user": urllib.parse.unquote(parsed.username or ""),
            "password": urllib.parse.unquote(parsed.password or ""),
            "host": parsed.hostname or "",
            "port": parsed.port,
            "params": dict(urllib.parse.parse_qsl(parsed.query)),
            "name": urllib.parse.unquote(parsed.fragment or ""),
        })
        return out
    raise ValueError("esquema no reconocido (se esperan v2rayng://, "
                     "vmess://, vless://, trojan://, ss://, hy2://)")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _read_input(path: str | None, use_stdin: bool) -> str:
    if use_stdin:
        return sys.stdin.read()
    if path is None:
        raise SystemExit("falta el archivo de entrada (o usa --stdin)")
    data = Path(path).read_bytes()
    if len(data) > MAX_FILE_BYTES:
        raise SystemExit("archivo mayor de 2 MB (limite de la app)")
    return data.decode("utf-8", "replace")


def _emit(data, out_path: str | None, redacted: bool = False) -> None:
    if out_path:
        Path(out_path).write_text(
            json.dumps(data, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
        print(f"escrito: {out_path}")
    else:
        print(json.dumps(data, ensure_ascii=False, indent=2))


def self_test() -> int:
    """Round-trips sinteticos + vectores fijos (sin red)."""
    failures = []

    def check(label, fn):
        try:
            fn()
            print(f"  OK  {label}")
        except Exception as exc:  # noqa: BLE001
            failures.append(label)
            print(f"  FAIL {label}: {exc}")

    # Vectores fijos (salt/nonce fijos; si el algoritmo cambia, fallan).
    vec_p17_net = (
        "ABEiM0RVZneImaq7zN3u/wECAwQFBgcICQoLDPxO14/jxFJ9duBWeYMe2NNc/"
        "FNVyavBXAa/3D53JN1ca0+EuvRC280uUoL4up0ypukeZJ/2AkJHeU66xc6uj7pVe7EQiUAukQUsSqPPJeUSz3Z/KNH9XAI="
    )
    vec_p32_cat = (
        "/+7dzLuqmYh3ZlVEMyIRAAwLCgkIBwYFBAMCAU30jR2Ms8fylF+i8sABqleS6J2I7ChlylkU0F4BEN9JPBakaH8vpP2A+FVo0OQy/SoDWCqsU1SdLxTwp6g="
    )
    vec_p17_field = (
        "ASNFZ4mrze/+3LqYdlQyEKq7zN3u/wARIjNEVWLhB48b+ZM+XZon9EIsM8tE+q9EnwTfD4AgbQ=="
    )
    vec_p17_empty = (
        "ABEiM0RVZneImaq7zN3u/wECAwQFBgcICQoLDMtbD+0iHx5JZ7sW38zgZWU="
    )

    def t_vec_p17():
        pt = decrypt_do(vec_p17_net)
        assert json.loads(pt)["Name"] == "TEST-NET", pt

    def t_vec_p32():
        pt = decrypt_live(vec_p32_cat)
        assert json.loads(pt)["Version"] == "9.99", pt

    def t_vec_field():
        assert decrypt_do(vec_p17_field) == b"203.0.113.7"

    def t_vec_empty():
        assert decrypt_do(vec_p17_empty) == b""

    def t_roundtrip_p17():
        net = {"Name": "TEST-NET", "TunnelType": "SSL Direct",
               "Payload": "GET / HTTP/1.1"}
        blob = encrypt_eo(json.dumps(net).encode())
        assert json.loads(decrypt_do(blob)) == net

    def t_roundtrip_p32():
        cat = {"Version": "9.99", "Servers": [], "Networks": []}
        blob = encrypt_live(json.dumps(cat).encode())
        assert json.loads(decrypt_live(blob)) == cat

    def t_txtunnel_roundtrip():
        net = {"Name": "SYNTH-NET", "TunnelType": "V2ray",
               "V2rayConfig": "x"}
        blob = export_txtunnel(net)
        data, route = import_txtunnel_content(blob)
        assert data == net and route == "A/parseConfig-P32", (data, route)
        # Ruta B (P17) tambien debe importar:
        blob_b = encrypt_eo(json.dumps(net).encode())
        data_b, route_b = import_txtunnel_content(blob_b)
        assert data_b == net and route_b == "B/DO-P17", (data_b, route_b)

    def t_v2rayng():
        vmess = "vmess://" + base64.urlsafe_b64encode(
            json.dumps({"v": "2", "ps": "SYNTH", "add": "203.0.113.7",
                        "port": "443", "id": "00000000-0000-0000-0000-000000000000",
                        "aid": "0", "net": "ws", "type": "none",
                        "host": "", "path": "", "tls": ""}).encode()
        ).decode().rstrip("=")
        parsed = parse_v2rayng_link(f"v2rayng://install-config?url={urllib.parse.quote(vmess)}")
        assert parsed["kind"] == "vmess" and parsed["config"]["ps"] == "SYNTH"
        parsed2 = parse_v2rayng_link(
            "vless://00000000-0000-0000-0000-000000000000@203.0.113.7:443"
            "?encryption=none&security=tls&sni=example.com&type=ws#SYNTH-VLESS")
        assert parsed2["kind"] == "vless" and parsed2["host"] == "203.0.113.7"

    def t_versions():
        assert compare_versions("66.87", "2.0") == 1
        assert compare_versions("2.0", "2.0") == 0
        assert compare_versions("1.9", "2.0") == -1

    def t_audit():
        # Catalogo sintetico ya descifrado: hex puros, cert en claro
        # y enlace vmess son VALORES, no cifrado -> 0 restantes.
        cat = {"Version": "9.99",
               "Servers": [{"Name": "S", "ServerIPHost": "203.0.113.7",
                            "SlowDNSKey": "a1b2c3d4a1b2c3d4a1b2c3d4a1b2c3d4"
                                            "a1b2c3d4a1b2c3d4a1b2c3d4a1b2c3d4",
                            "OVPNUser": "1234567890abcdef1234567890abcdef",
                            "CustomCertificate": "client\ndev tun\n"
                            "-----BEGIN CERTIFICATE-----\n"
                            "MIICMTCCAZqgAwIBAgIUAaQBApMS2dYBqYPcA3Pa7cjjw7cw==\n"
                            "-----END CERTIFICATE-----"}],
               "Networks": [{"Name": "N", "V2rayConfig":
                             "vmess://eyJhZGQiOiIxMjcuMC4wLjEifQ==",
                             "Payload": "GET / HTTP/1.1"}]}
        audit = audit_decrypted_catalog(cat)
        assert audit["ok"] and audit["remaining"] == [], audit
        assert audit["hex_values"].get("SlowDNSKey") == 1, audit
        assert audit["hex_values"].get("OVPNUser") == 1, audit
        # Un sobre P17 sin descifrar SI debe aparecer como restante.
        cat2 = {"Servers": [{"ServerIPHost": vec_p17_field}]}
        audit2 = audit_decrypted_catalog(cat2)
        assert not audit2["ok"] and len(audit2["remaining"]) == 1, audit2

    def t_generic_fields():
        # El descifrado generico cubre tambien el nivel superior y
        # campos fuera de las listas antiguas.
        blob = encrypt_eo(b"203.0.113.9")
        cat = {"Version": "9.99", "TopSecret": blob,
               "Servers": [{"Name": "S", "NewField": blob,
                            "SlowDNSKey": "a1b2c3d4a1b2c3d4a1b2c3d4a1b2c3d4"
                                            "a1b2c3d4a1b2c3d4a1b2c3d4a1b2c3d4"}],
               "Networks": []}
        out, stats = decrypt_catalog_fields(cat)
        assert out["TopSecret"] == "203.0.113.9", out
        assert out["Servers"][0]["NewField"] == "203.0.113.9", out
        assert out["Servers"][0]["SlowDNSKey"].startswith("a1b2c3d4"), out
        assert stats["ok"] == 2, stats
        assert audit_decrypted_catalog(out)["ok"], out
        # El recorrido paralelo debe dar exactamente lo mismo.
        out_par, stats_par = decrypt_catalog_fields(cat, workers=2)
        assert out_par == out, "paralelo difiere del secuencial"
        assert stats_par == stats, stats_par

    def t_redact():
        cat = {"Version": "9.99", "DefOVPNUser": "u",
               "Servers": [{"Name": "S", "ServerIPHost": "1.2.3.4",
                            "OpenVPNTCPPort": "110"}],
               "Networks": [{"Name": "N", "Payload": "xxx",
                             "TunnelType": "SSL Direct"}]}
        red = redact_catalog(cat)
        assert red["Servers"][0]["ServerIPHost"] == REDACTED
        assert red["Servers"][0]["OpenVPNTCPPort"] == "110"
        assert red["Networks"][0]["Payload"] == REDACTED
        assert red["DefOVPNUser"] == REDACTED
        assert "txtunnelnew" not in json.dumps(red)

    print("self-test txtunnel (sin red):")
    for label, fn in (
        ("vector fijo P17 (network)", t_vec_p17),
        ("vector fijo P32 (catalogo)", t_vec_p32),
        ("vector fijo P17 (campo)", t_vec_field),
        ("vector fijo P17 (vacio)", t_vec_empty),
        ("round-trip EO/DO (P17)", t_roundtrip_p17),
        ("round-trip Encrypt/decrypt (P32)", t_roundtrip_p32),
        (".txtunnel export/import (P32 y P17)", t_txtunnel_roundtrip),
        ("v2rayng:// sintetico", t_v2rayng),
        ("compare_versions", t_versions),
        ("redact_catalog", t_redact),
        ("auditoria catalogo descifrado (hex/cert/vmess)", t_audit),
        ("descifrado generico de campos (top + nuevos)", t_generic_fields),
    ):
        check(label, fn)
    if failures:
        print(f"SELF-TEST: {len(failures)} fallos: {failures}")
        return 1
    print("SELF-TEST: todo OK")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Decodificador Tx Tunnel (catalogo, .txtunnel, v2rayng://)"
    )
    parser.add_argument("file", nargs="?", help="configfile.json o .txtunnel")
    parser.add_argument("--fetch", action="store_true",
                        help="descargar el catalogo vivo (POST txtunnelnew)")
    parser.add_argument("--text", help="enlace v2rayng:// / vmess:// / ...")
    parser.add_argument("--stdin", action="store_true",
                        help="leer el contenido desde stdin")
    parser.add_argument("--out", help="archivo JSON de salida")
    parser.add_argument("--redacted", action="store_true",
                        help="redactar credenciales (para ZIP/Drive)")
    parser.add_argument("--full-fields", action="store_true",
                        help="con --fetch: descifrar tambien los campos "
                             "individuales (lento, ~miles de Argon2)")
    parser.add_argument("--workers", type=int, default=0,
                        help="con --full-fields: procesos en paralelo para "
                             "descifrar campos (4 recomendado; 0 = secuencial)")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args(argv)

    if args.self_test:
        return self_test()

    if args.fetch:
        print("descargando catalogo vivo (POST txtunnelnew)...")
        catalog = fetch_live_catalog()
        summary = catalog_summary(catalog)
        print(f"vivo: Version {summary['Version']}, "
              f"{summary['servers']} servidores, "
              f"{summary['networks']} networks")
        if args.full_fields:
            print("descifrando campos individuales (P17/P32, generico)...")
            catalog, stats = decrypt_catalog_fields(catalog,
                                                    workers=args.workers)
            print(f"campos: ok={stats['ok']} (P17={stats['ok_p17']}, "
                  f"P32={stats['ok_p32']}) vacios={stats['empty44']} "
                  f"sin-sobre={stats['kept']} fallidos={stats['failed']}")
            audit = audit_decrypted_catalog(catalog)
            print(f"auditoria: cifrados_restantes={len(audit['remaining'])} "
                  f"hex_valores={audit['hex_values']}")
            if not audit["ok"]:
                for path, preview in audit["remaining"]:
                    print(f"  SIN DESCIFRAR: {path}: {preview}", file=sys.stderr)
                _emit(catalog, args.out)
                print("auditoria: quedan valores cifrados sin descifrar "
                      "(ver arriba)", file=sys.stderr)
                return 1
        if args.redacted:
            catalog = redact_catalog(catalog)
        _emit(catalog, args.out)
        return 0

    if args.text:
        try:
            _emit(parse_v2rayng_link(args.text), args.out)
        except ValueError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 1
        return 0

    content = _read_input(args.file, args.stdin)
    # 1) .txtunnel / network cifrado (P32, P17 o JSON plano)
    try:
        data, route = import_txtunnel_content(content)
        print(f".txtunnel importado por ruta {route}")
        _emit(data, args.out)
        return 0
    except ValueError:
        pass
    # 2) sobre del catalogo (P17 incluido / P32 vivo)
    try:
        plaintext, which = decrypt_catalog_envelope(content)
        catalog = json.loads(plaintext.decode("utf-8"))
        print(f"catalogo descifrado ({which}): Version "
              f"{catalog.get('Version')}, {len(catalog.get('Servers', []))} "
              f"servidores, {len(catalog.get('Networks', []))} networks")
        if args.redacted:
            catalog = redact_catalog(catalog)
        _emit(catalog, args.out)
        return 0
    except (ValueError, json.JSONDecodeError) as exc:
        print(f"error: no se pudo descifrar el contenido: {exc}",
              file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

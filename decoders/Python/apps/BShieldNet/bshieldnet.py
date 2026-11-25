#!/usr/bin/env python3
"""B SHIELD NET 2.9 (29) — decodificador de archivos, textos y catalogo vivo.

Paquete ``xyz.bshieldnet.org``; familia RENZ (v2rayNG + RENZ). El perfil
RENZ ``bshield`` YA esta registrado en ``decoders/Python/renz.py``:
``.bshield`` en ``RENZ_FILE_EXTENSIONS`` y ``bshieldnet://`` /
``bshield://`` en ``RENZ_TEXT_PROTOCOLS``. Este script despacha a esa
ruta sin duplicar ninguna constante de claves.

Metodo (perfil ``bshield``, verificado en vivo 2026-11-24):
  sobre exterior: Base64 -> AES-128-CBC (clave = SHA-256(KEY_SEED)[:16],
  IV fijo, PKCS7) -> XXTEA custom (delta 0x7A56D3E1, 6 + 52/n rondas)
  -> restar 2 a cada byte -> JSON;
  pase interior recursivo (``renz_recursive_decrypt_main``): cada campo
  de texto del JSON se prueba con los descifradores RENZ tipo 0/1/2/3
  (HKDF/PBKDF2 + Threefish/AES/XXTEA); los campos que no abren con
  ningun modo quedan como estan, nunca inventados.

Catalogo vivo: GET plano (sin auth, sin body, sin headers especiales) a
  https://raw.githubusercontent.com/snapb/B-SHIELD-NET-2026/refs/heads/main/b_shield_net_2026
  Respuesta: una sola linea Base64 (911.897 bytes el 2026-11-24 22:35 UTC).
  Descifrada en el primer intento con el perfil ``bshield``:
  Version 7.34, 90 servidores, 792 networks (payloads).

  El catalogo COMPLETO lleva credenciales de servidor (usuario,
  contrasena, host, UUID V2Ray, certificados). Como el precedente de
  Ways Tunnel: el catalog.json completo va SOLO como adjunto del chat,
  NUNCA en Drive ni en el ZIP. Para el ZIP/Drive usar la copia
  redactada (``fetch --redacted``).

Uso::

    python bshieldnet.py --fetch [--out catalog.json] [--redacted]
    python bshieldnet.py perfil.bshield
    python bshieldnet.py --text 'bshieldnet://<payload>'
    python bshieldnet.py --text 'bshield://<payload>'
    python bshieldnet.py --stdin < perfil.bshield
    python bshieldnet.py --self-test

El JSON de resultado solo lleva los datos del perfil descifrado; no hay
creditos dentro del script ni de sus resultados, ni URLs de descarga de
catalogo en el JSON de resultado (la URL solo vive en el modo fetch).

Estado: catalogo VERIFIED_REAL (descarga + descifrado en vivo).
Archivos .bshield y textos bshieldnet:///bshield:// VERIFIED_SYNTHETIC
(round-trip sintetico; ver tests/test_bshieldnet_file_text.py). Sin
muestra real de .bshield ni de enlace todavia, asi que NO son
VERIFIED_REAL. Dossier: analysis/xyz.bshieldnet.org/29/.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import struct
import sys
import urllib.request
from pathlib import Path

# Localiza renz.py sin depender del cwd: primero junto al script (ZIP
# entregable, donde renz.py va copiado al lado de bshieldnet.py), luego
# en el layout del repo SP-DECODE (este archivo vive en
# decoders/Python/apps/BShieldNet/, asi que parents[2] es
# decoders/Python, donde vive renz.py), y luego en el worktree local.
_CANDIDATES = (
    Path(__file__).resolve().parent,
    Path(__file__).resolve().parents[2],
    Path(__file__).resolve().parents[1] / "spdecode-patch" / "decoders" / "Python",
    Path(__file__).resolve().parents[2] / "spdecode-patch" / "decoders" / "Python",
    Path(__file__).resolve().parent / "decoders" / "Python",
)
for _candidate in _CANDIDATES:
    if (_candidate / "renz.py").is_file():
        if str(_candidate) not in sys.path:
            sys.path.insert(0, str(_candidate))
        break
else:  # pragma: no cover - renz.py ausente
    raise ImportError("No se encontro decoders/Python/renz.py en el worktree SP-DECODE")

import renz as shared  # noqa: E402

MAX_BYTES = 2 * 1024 * 1024  # mismo limite que renz.MAX_INPUT_BYTES
PROFILE = "bshield"  # perfil RENZ verificado para B SHIELD NET 2.9
APPLICATION = "RENZ / BSHIELD"
EXTENSION = ".bshield"
SCHEMES = ("bshieldnet://", "bshield://")
CATALOG_URL = ("https://raw.githubusercontent.com/snapb/B-SHIELD-NET-2026/"
               "refs/heads/main/b_shield_net_2026")

# Claves de credencial/configuracion que la copia redactada sustituye.
_REDACT_KEYS = {"Username", "Password", "ServerIPHost", "CustomCert", "UUID"}


class DecodeError(ValueError):
    pass


def _decode_payload(payload: str):
    """Descifra un payload Base64 con el perfil bshield (ruta RENZ)."""
    config = shared._decode_config(payload.strip(), PROFILE)
    if config is None:
        raise DecodeError("Perfil B SHIELD NET invalido.")
    return config


def decode_file_bytes(data: bytes) -> dict:
    """Decodifica el contenido de un archivo .bshield a documento dict."""
    if not isinstance(data, bytes) or not data or len(data) > MAX_BYTES:
        raise DecodeError("Perfil vacio o superior a 2 MiB.")
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        raise DecodeError("Perfil B SHIELD NET invalido (no es texto UTF-8).") from None
    doc = shared.decode_file(data, EXTENSION)
    if doc is None:
        raise DecodeError("Perfil B SHIELD NET invalido.")
    return json.loads(doc)


def decode_link(text: str) -> dict:
    """Decodifica un enlace bshieldnet:// o bshield:// a documento dict."""
    if not text or len(text.encode("utf-8")) > MAX_BYTES:
        raise DecodeError("Enlace vacio o superior a 2 MiB.")
    raw = text.strip()
    if "://" not in raw:
        raise DecodeError("Enlace sin esquema (se esperaba bshieldnet:// o bshield://).")
    prefix, payload = raw.split("://", 1)
    scheme = prefix.lower() + "://"
    if scheme not in SCHEMES or not payload.strip():
        raise DecodeError("Enlace no valido para B SHIELD NET (se esperaba bshieldnet:// o bshield://).")
    doc = shared.decode_text(raw)
    if doc is None:
        raise DecodeError("Enlace B SHIELD NET invalido.")
    return json.loads(doc)


def fetch_catalog(url: str = CATALOG_URL, timeout: int = 60) -> tuple[dict, dict]:
    """GET plano al catalogo vivo y descifrado con el perfil bshield.

    Devuelve (catalogo, meta) donde meta trae http_status, bytes y
    sha256 del blob crudo. No imprime ningun contenido del catalogo.
    """
    with urllib.request.urlopen(url, timeout=timeout) as resp:  # noqa: S310 - URL fija del proveedor
        status = resp.status
        raw = resp.read()
    if status != 200:
        raise DecodeError(f"Catalogo HTTP {status}.")
    blob = raw.strip()
    if len(blob) > 4 * 1024 * 1024:
        raise DecodeError("Catalogo mayor de 4 MiB.")
    catalog = _decode_payload(blob.decode("ascii"))
    if not isinstance(catalog, dict) or "Servers" not in catalog or "Networks" not in catalog:
        raise DecodeError("Catalogo descifrado sin Servers/Networks.")
    meta = {
        "url": url,
        "http_status": status,
        "blob_bytes": len(blob),
        "blob_sha256": hashlib.sha256(blob).hexdigest(),
        "catalog_version": catalog.get("Version"),
        "servers": len(catalog.get("Servers", [])),
        "networks": len(catalog.get("Networks", [])),
    }
    return catalog, meta


def redact_catalog(catalog: dict) -> dict:
    """Copia del catalogo con credenciales/config de servidor redactadas.

    Sustituye Username, Password, ServerIPHost, CustomCert y V2Ray.UUID
    por "[redacted]". Conserva nombres, banderas, protocolos, puertos,
    payloads y notas: todo lo que SP-DECODE muestra sin credenciales.
    """
    def walk(obj):
        if isinstance(obj, dict):
            return {k: ("[redacted]" if k in _REDACT_KEYS and isinstance(v, str) else walk(v))
                    for k, v in obj.items()}
        if isinstance(obj, list):
            return [walk(v) for v in obj]
        return obj
    return walk(catalog)


def run(data: bytes) -> str:
    """Entrada de archivo .bshield (bytes) -> JSON de resultado."""
    return json.dumps(decode_file_bytes(data), ensure_ascii=False, indent=2) + "\n"


def run_text(text: str) -> str:
    """Entrada de texto bshieldnet:///bshield:// -> JSON de resultado."""
    return json.dumps(decode_link(text), ensure_ascii=False, indent=2) + "\n"


# --- Generador inverso (SOLO para self-test y fixtures) -------------------
# Inverso exacto del sobre exterior RENZ (AES-128-CBC + XXTEA custom +
# +2 por byte). Verificado byte-identico contra el blob vivo del catalogo
# (re-cifrado del plaintext vivo == blob original). La app nunca cifra;
# esto solo construye muestras sinteticas para probar el descifrador.

def _xxtea_encrypt_custom(payload: bytes, key: bytes) -> bytes:
    delta, offset = shared.RENZ_DELTA_V2, shared.RENZ_OFFSET_V2
    words = shared.renz_xxtea_to_uint32(payload, True)
    n = len(words)
    if n < 2:
        raise ValueError("XXTEA sintetico necesita mas de una palabra")
    k = shared.renz_prepare_key_xxtea(key)
    rounds = 52 // n + 6
    total = 0
    for _ in range(rounds):
        total = (total + delta) & 0xFFFFFFFF
        e = (total >> 2) & 3
        z = words[-1]
        for p in range(n - 1):
            y = words[p + 1]
            words[p] = (words[p] + shared.renz_mx(total, y, z, p, e, k)) & 0xFFFFFFFF
            z = words[p]
        words[-1] = (words[-1] + shared.renz_mx(total, words[0], z, n - 1, e, k)) & 0xFFFFFFFF
    assert total == ((52 // n) * delta - offset) & 0xFFFFFFFF
    return struct.pack("<%dI" % n, *words)


def encrypt_profile(config: dict) -> bytes:
    """Cifra un perfil con el metodo RENZ del perfil bshield (sobre exterior)."""
    from Crypto.Cipher import AES
    from Crypto.Util.Padding import pad
    data = json.dumps(config, ensure_ascii=False).encode("utf-8")
    spec = shared.RENZ_KEYS[PROFILE]
    key = hashlib.sha256(spec["KEY_SEED"]).digest()[:16]
    transformed = bytes((b + 2) & 255 for b in data)
    blob = _xxtea_encrypt_custom(transformed, key)
    cipher = AES.new(key, AES.MODE_CBC, iv=spec["IV"])
    return base64.b64encode(cipher.encrypt(pad(blob, 16)))


def self_test() -> int:
    """Round-trip sintetico: cifra un perfil ficticio y lo descifra de vuelta."""
    profile = {
        "Version": "7.34",
        "Servers": [{
            "Name": "TEST SERVER",
            "ServerIPHost": "test.invalid",
            "Subname": "Test",
            "OpenVPNTCPPort": "1194",
            "OpenVPNSSLPort": "443",
            "Protocol": 0,
            "flag": "mx",
            "Username": "test-user",
            "Password": "test-pass",
        }],
        "Networks": [{
            "Name": "TEST PAYLOAD",
            "SNIHost": "test.invalid",
            "Payload": "GET / HTTP/1.1[crlf]Host: test.invalid[crlf][crlf]",
            "ServerProtocol": 0,
            "TunnelType": 7,
        }],
    }
    payload = encrypt_profile(profile)
    doc_file = decode_file_bytes(payload)
    assert doc_file["config"] == profile, "round-trip .bshield fallo"
    for scheme in SCHEMES:
        doc_text = decode_link(scheme + payload.decode("ascii"))
        assert doc_text["config"] == profile, f"round-trip {scheme} fallo"
    # Rechazo: truncado y basura no deben abrir.
    assert shared.decode_file(payload[:100], EXTENSION) is None, "truncado abrio"
    assert shared.decode_text("bshieldnet://AAAA") is None, "basura abrio"
    print("self-test OK: .bshield + bshieldnet:// + bshield:// round-trip, "
          "rechazo de truncado/basura OK")
    return 0


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("file", nargs="?", type=Path,
                   help="Archivo .bshield (si se omite, lee stdin)")
    p.add_argument("--text", metavar="ENLACE",
                   help="Decodifica un enlace bshieldnet:// o bshield:// en vez de un archivo")
    p.add_argument("--stdin", action="store_true",
                   help="Lee la entrada de stdin")
    p.add_argument("--self-test", action="store_true",
                   help="Round-trip sintetico sin red")
    p.add_argument("--fetch", action="store_true",
                   help="Descarga el catalogo vivo (uso: bshieldnet.py --fetch)")
    p.add_argument("--out", type=Path, default=Path("catalog.json"),
                   help="Destino del catalogo descargado (por defecto catalog.json)")
    p.add_argument("--redacted", action="store_true",
                   help="Con fetch: escribe la copia redactada (catalog-redacted.json)")
    a = p.parse_args()
    try:
        if a.self_test:
            return self_test()
        if a.fetch:
            catalog, meta = fetch_catalog()
            out = a.out
            data = catalog
            if a.redacted:
                data = redact_catalog(catalog)
                if out.name == "catalog.json":
                    out = Path("catalog-redacted.json")
            out.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n",
                           encoding="utf-8")
            print(f"Catalogo v{meta['catalog_version']}: {meta['servers']} servidores, "
                  f"{meta['networks']} networks — HTTP {meta['http_status']}, "
                  f"{meta['blob_bytes']} bytes, sha256 {meta['blob_sha256'][:16]}…")
            print(f"Escrito en {out}")
            if not a.redacted:
                print("AVISO: el catalogo completo lleva credenciales de servidor; "
                      "va SOLO como adjunto del chat, NUNCA en Drive ni en el ZIP. "
                      "Usa --redacted para la copia del ZIP.")
            return 0
        if a.text is not None:
            if a.text == "-":
                sys.stdout.write(run_text(sys.stdin.read()))
            else:
                sys.stdout.write(run_text(a.text))
        else:
            if a.file:
                with a.file.open("rb") as stream:
                    data = stream.read(MAX_BYTES + 1)
            else:
                data = sys.stdin.buffer.read(MAX_BYTES + 1)
            # stdin puede traer un enlace pegado en vez de un archivo.
            if data.decode("utf-8", errors="ignore").strip().lower().startswith(
                    ("bshieldnet://", "bshield://")):
                sys.stdout.write(run_text(data.decode("utf-8")))
            else:
                sys.stdout.write(run(data))
        return 0
    except (ValueError, OSError) as exc:
        print(f"No se pudo procesar: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

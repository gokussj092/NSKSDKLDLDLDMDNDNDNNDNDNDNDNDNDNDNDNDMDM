#!/usr/bin/env python3
"""HTTP Injector 6.5.0/244: importación cloud, independiente del lector .ehi.

Necesita HTTPINJECTOR.py en este mismo directorio, pycryptodome y argon2-cffi.
decode_cloud() devuelve JSON tipado; run(bytes) conserva la interfaz del bot.
Los enlaces son referencias a servidor: la descarga requiere Internet.
"""
import argparse
import base64
import binascii
import hashlib
import hmac
import json
from pathlib import Path
import re
import struct
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
import zlib

if __package__:
    from . import HTTPINJECTOR as ehi
else:
    import HTTPINJECTOR as ehi

ENDPOINT = "https://www.ehi.tools/httpinjector/import_config"
APP_BUILD = "244"
SIGN_SECRET = "xn1WSCjY25RKW1pDQr0s3cdg6VSiQLb0"
# Son 32 bytes UTF-8 literales, NO se decodifica esta clave como Base64.
API_KEY = b"GialHt24BQOZ+pwUE2++82H/EtnTqFh4"
MAX_RESPONSE_BYTES = 8 * 1024 * 1024
MAX_INFLATED_BYTES = 8 * 1024 * 1024
KEY_RE = re.compile(r"[A-Za-z0-9_]{1,128}\Z", re.ASCII)


class CloudError(ValueError):
    """Error explícito de formato, red, servidor o autenticación criptográfica."""


def parse_reference(reference):
    if isinstance(reference, bytes):
        try:
            reference = reference.decode("utf-8-sig")
        except UnicodeError as exc:
            raise CloudError("La referencia cloud no es texto UTF-8.") from exc
    if not isinstance(reference, str):
        raise CloudError("Se esperaba un enlace cloud o una clave de configuración.")
    reference = reference.strip()
    if KEY_RE.fullmatch(reference):
        return reference
    try:
        url = urllib.parse.urlsplit(reference)
    except ValueError as exc:
        raise CloudError("El enlace cloud está mal formado.") from exc
    if (url.scheme not in ("https", "ehi") or url.netloc != "ehi.link"
            or url.query or url.fragment or not url.path.startswith("/")):
        raise CloudError("Usa https://ehi.link/CLAVE, ehi://ehi.link/CLAVE o CLAVE.")
    key = url.path[1:]
    if not KEY_RE.fullmatch(key):
        raise CloudError("La clave del enlace cloud tiene caracteres o longitud inválidos.")
    return key


def java_urlencode(value):
    """URLEncoder UTF-8 del interceptor: '+' se sustituye por '%2B'."""
    return (urllib.parse.quote_plus(str(value), safe="*-._")
            .replace("~", "%7E").replace("+", "%2B"))


def build_request(config_key, *, timestamp=None, nonce=None, identity=None):
    """Replica yk0 con SignKeys(null, null, Constant.ࡶ); no credenciales personales."""
    config_key = parse_reference(config_key)
    identity = identity or str(uuid.uuid4())
    headers = {
        "x-nonce": nonce or str(uuid.uuid4()),
        "x-timestamp": str(int(time.time()) if timestamp is None else timestamp),
        "x-sign-version": "1.0",
        "x-uid": hashlib.sha1(identity.encode("utf-8")).hexdigest().upper(),
        "x-did": hashlib.md5(identity.encode("utf-8")).hexdigest().upper(),
        "x-platform": "android",
        "x-device": "Android",
        "x-os-api": "35",
        "x-app-build": APP_BUILD,
    }
    # config_key no incluye '+', '%' ni espacios; la normalización del cuerpo
    # de la app lo deja intacto. Los valores firmados NO se vuelven a decodificar.
    params = dict(headers, config_key=config_key)
    normalized = "&".join(k + "=" + params[k] for k in sorted(params))
    canonical = "&".join(java_urlencode(s) for s in ("POST", ENDPOINT, normalized))
    signing_key = java_urlencode("-1") + "&" + java_urlencode(SIGN_SECRET)
    signature = hmac.new(signing_key.encode(), canonical.encode(), hashlib.sha1).digest()
    headers["x-signature"] = java_urlencode(base64.b64encode(signature).decode("ascii"))
    headers["Content-Type"] = "application/x-www-form-urlencoded"
    headers["Accept"] = "application/json"
    headers["User-Agent"] = "okhttp/4.12.0"
    return ("config_key=" + config_key).encode("ascii"), headers


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise CloudError("El endpoint de importación redirigió; revisa la versión de la app.")


def fetch_response(config_key, timeout=20):
    body, headers = build_request(config_key)
    request = urllib.request.Request(ENDPOINT, data=body, headers=headers, method="POST")
    try:
        with urllib.request.build_opener(_NoRedirect()).open(request, timeout=timeout) as response:
            raw = response.read(MAX_RESPONSE_BYTES + 1)
    except urllib.error.HTTPError as exc:
        if exc.code == 401:
            raise CloudError("HTTP 401: firma o reloj rechazados; revisa la versión de la app.") from exc
        raise CloudError(f"El servidor cloud respondió HTTP {exc.code}.") from exc
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise CloudError("No se pudo contactar al servidor cloud; comprueba red y reloj.") from exc
    if len(raw) > MAX_RESPONSE_BYTES:
        raise CloudError("La respuesta cloud supera el límite de tamaño.")
    return raw


def _json_object(raw, layer):
    try:
        value = json.loads(raw)
    except (ValueError, UnicodeError, TypeError) as exc:
        raise CloudError(f"JSON inválido en {layer}.") from exc
    if not isinstance(value, dict):
        raise CloudError(f"Se esperaba un objeto JSON en {layer}.")
    return value


def _base64(value, layer):
    if not isinstance(value, str) or len(value) > MAX_RESPONSE_BYTES:
        raise CloudError(f"Base64 ausente o demasiado grande en {layer}.")
    try:
        return base64.b64decode(value, validate=True)
    except (ValueError, binascii.Error) as exc:
        raise CloudError(f"Base64 inválido en {layer}.") from exc


def _inflate(compressed):
    try:
        inflater = zlib.decompressobj()
        plaintext = inflater.decompress(compressed, MAX_INFLATED_BYTES + 1)
        if len(plaintext) > MAX_INFLATED_BYTES or inflater.unconsumed_tail:
            raise CloudError("La respuesta descomprimida supera el límite de tamaño.")
        if not inflater.eof or inflater.unused_data:
            raise CloudError("El flujo zlib está truncado o contiene datos adicionales.")
        return plaintext
    except zlib.error as exc:
        raise CloudError("El contenido cloud no es un flujo zlib válido.") from exc


def decrypt_api_response(response, audit=None):
    """JSON externo -> HMAC(ciphertext) -> AES-CBC -> zlib -> JSON ImportConfig."""
    if not isinstance(response, (bytes, str, dict)):
        raise CloudError("Tipo de respuesta cloud inválido.")
    if isinstance(response, (bytes, str)) and len(response) > MAX_RESPONSE_BYTES:
        raise CloudError("La respuesta cloud supera el límite de tamaño.")
    envelope = response if isinstance(response, dict) else _json_object(response, "respuesta HTTP")
    if envelope.get("code") != 200:
        raise CloudError("El servidor no aceptó la importación cloud (code != 200).")
    raw = _base64(envelope.get("data"), "data")
    if len(raw) < 64 or (len(raw) - 48) % 16:
        raise CloudError("El contenedor cloud AES está truncado o tiene longitud inválida.")
    iv, tag, ciphertext = raw[:16], raw[16:48], raw[48:]
    expected = hmac.new(API_KEY, ciphertext, hashlib.sha256).digest()
    if not hmac.compare_digest(tag, expected):
        raise CloudError("HMAC-SHA256 inválido: la respuesta cloud fue alterada o cambió la clave.")
    try:
        compressed = ehi._aes_cbc_decrypt(ciphertext, API_KEY, iv)
    except ValueError as exc:
        raise CloudError("Padding AES-CBC inválido en la respuesta cloud.") from exc
    plaintext = _inflate(compressed)
    imported = _json_object(plaintext, "ImportConfig")
    if imported.get("status") != "success":
        raise CloudError("El enlace cloud no está disponible o el servidor rechazó su importación.")
    if audit is not None:
        audit.update({
            "api_envelope_sha256": hashlib.sha256(raw).hexdigest(),
            "api_hmac_verified": True,
            "api_hmac_covers": "ciphertext (el IV no está incluido por el formato de la app)",
            "import_json_bytes": len(plaintext),
        })
    return imported


def decode_response(response, audit=None):
    if audit is not None:
        audit.clear()
    imported = decrypt_api_response(response, audit)
    payload = _base64(imported.get("config_data"), "config_data")
    if not payload or len(payload) % 16:
        raise CloudError("config_data no contiene un payload CBC válido.")
    # Cloud entrega el ciphertext EHI SIN su cabecera DataInputStream. Esta
    # cabecera es sólo un adaptador local al lector existente, no un archivo
    # original ni un paso criptográfico. No modifica claves ni los seis perfiles.
    adapter = (b"\x00\x03ehi" + bytes(8) + b"\x00\x03" + APP_BUILD.encode("ascii")
               + bytes(8) + struct.pack(">I", len(payload)) + bytes(8) + payload)
    payload_audit = {}
    document = ehi.decode_ehi(adapter, payload_audit)
    if document is None:
        raise CloudError("config_data no pudo autenticarse/descifrarse con los perfiles EHI existentes.")
    if audit is not None:
        # No atribuir el SHA de la cabecera artificial a un archivo real.
        payload_audit["adapter_sha256"] = payload_audit.pop("input_sha256")
        audit.update({
            "transport": "http-injector-cloud",
            "app_version": "6.5.0/244",
            "config_ciphertext_sha256": hashlib.sha256(payload).hexdigest(),
            "ehi": payload_audit,
            "achilles_present": "achilles" in imported,
            "achilles_verified": False,
            "note": "achilles se conserva en la respuesta original; no se afirma verificarlo.",
        })
    return document


def decode_cloud(reference, audit=None, *, timeout=20):
    return decode_response(fetch_response(parse_reference(reference), timeout), audit)


def run(file_bytes):
    """Interfaz del bot; usar decode_cloud para conocer el error preciso."""
    try:
        return ehi._format_ehi_document(decode_cloud(file_bytes)).replace("(.ehi)", "(cloud)", 1)
    except CloudError:
        return None


def read_source(source):
    try:
        path = Path(source)
        if path.is_file():
            if path.stat().st_size > 4096:
                raise CloudError("El archivo de referencia es demasiado grande.")
            return path.read_bytes()
    except OSError:
        pass
    return source


def write_json(value, output=None):
    text = json.dumps(value, ensure_ascii=False, indent=2) + "\n"
    if output:
        Path(output).write_text(text, encoding="utf-8")
    else:
        print(text, end="")


def validate_output_paths(source, response, output, audit):
    inputs = []
    if response:
        inputs.append(Path(response).resolve())
    if source:
        try:
            if Path(source).is_file():
                inputs.append(Path(source).resolve())
        except OSError:
            pass
    targets = [Path(path).resolve() for path in (output, audit) if path]
    if len(set(targets)) != len(targets) or any(path in inputs for path in targets):
        raise CloudError("La entrada, la salida y la auditoría deben usar archivos diferentes.")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", nargs="?", help="enlace, clave cloud o archivo .txt UTF-8")
    parser.add_argument("--response", type=Path, help="descifrar una respuesta HTTP guardada, sin red")
    parser.add_argument("--json", action="store_true", help="JSON completo (salida predeterminada)")
    parser.add_argument("-o", "--output", help="archivo JSON de salida")
    parser.add_argument("--audit", help="informe JSON de verificaciones y transformaciones")
    args = parser.parse_args()
    if args.source is None and args.response is None:
        parser.error("indica un enlace/clave o --response")
    try:
        validate_output_paths(args.source, args.response, args.output, args.audit)
        audit = {}
        if args.response:
            with args.response.open("rb") as source:
                response = source.read(MAX_RESPONSE_BYTES + 1)
            document = decode_response(response, audit)
        else:
            document = decode_cloud(read_source(args.source), audit)
        write_json(document, args.output)
        if args.audit:
            write_json(audit, args.audit)
        return 0
    except (CloudError, OSError, ImportError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
#!/usr/bin/env python3
"""VC VPN 8.0 (com.vc.vpn): decodificador de archivos .tgv / .vcv.

Standalone Python 3.10+, standard library only; no APK needed at runtime.
Importa el descifrado de VC_VPN.py (mantener ambos archivos juntos).
See README.md here.

Formatos (verificados contra este APK, versionCode 80, versionName 8.0):

  .tgv — la app lo abre con un intent-filter VIEW en MainActivity
  (esquemas file/content, mimeType */*, pathPattern .*.tgv). El archivo
  es un texto con un sobre STGCM2.VC. / STGCM3.VC., el mismo sobre del
  catálogo: AES-256-GCM, claves KEY_CONFIG3 / KEY_CONFIG2 de VC_VPN.py,
  AAD = el prefijo con el punto final. Al descifrarlo sale un JSON
  (el catálogo completo, con Servers[] y Tweaks[], o un perfil suelto);
  los valores de cadena llevan la misma codificación que el catálogo
  (r95, "u8:" + Base64, "VCCR1." + AES-256-GCM con KEY_CRED).
  Este script lo abre igual que VC_VPN.py --file.

  .vcv — la app EXPORTA perfiles a Documents/<nombre app>/<nombre>.vcv
  (ExportActivity + iw0): el contenido es la salida cruda de
  TekProtect.nEncryptUserConfig(JSON {"VCV_CONFIG": <perfil>}), es
  decir, el perfil cifrado con la ruta de "config de usuario" de la
  librería nativa (libfrkudp.so, funciones nEncryptUserConfig /
  nDecryptUserConfig, 0xdab60 / 0xdbe00), que usa blobs .rodata
  propios (0x44d90 / 0x44e90) detrás de std::string de libc++.
  Ese sobre NO se pudo resolver offline: no existe ninguna muestra
  real de .vcv y la emulación Unicorn del descifrador se atasca en
  libc++ (basic_stringbuf::str). Este script DETECTA un .vcv (o
  cualquier texto que no sea un sobre STGCM ni JSON) y lo reporta
  como VCV_PENDING con su SHA-256 y tamaño, sin inventar contenido.
  Con una muestra real de .vcv se podrá completar el método.

  Sin formato propio de texto: la app no declara ningún esquema URI
  propio (no hay vcvpn:// ni similar); solo acepta los enlaces
  estándar vmess/vless/ss/trojan de la librería V2Ray ANG, ya
  cubiertos por SP-DECODE.

Uso:
  python3 VC_VPN_archivos.py --file perfil.tgv [-o salida.json]
  python3 VC_VPN_archivos.py --file perfil.vcv   # -> VCV_PENDING
  python3 VC_VPN_archivos.py --stdin < perfil.tgv
  python3 VC_VPN_archivos.py --self-test
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys

from VC_VPN import (
    DecodeError,
    _decode_values,
    _decrypt_envelope,
    _encrypt_envelope,
    _json,
    KEY_CONFIG2,
    KEY_CONFIG3,
)

MAX_BYTES = 5 * 1024 * 1024


class FileError(ValueError):
    """Error de archivo con un código estable para SP-DECODE."""

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


def _is_stgcm(text: str) -> bool:
    return text.startswith("STGCM3.VC.") or text.startswith("STGCM2.VC.")


def decode(data) -> dict:
    """Abre un archivo .tgv (sobre STGCM) o un JSON ya descifrado.

    Devuelve el dict decodificado (catálogo completo o perfil suelto).
    Un archivo .vcv (sobre nEncryptUserConfig) o cualquier otro texto
    que no abra se reporta como VCV_PENDING / DECRYPT_FAILED, nunca
    se inventa un perfil.
    """
    if isinstance(data, bytes):
        if len(data) > MAX_BYTES:
            raise FileError("SIZE_LIMIT", "El archivo supera el tamaño máximo.")
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise FileError("VCV_PENDING",
                            "El archivo no es texto UTF-8: parece un .vcv "
                            "(sobre nEncryptUserConfig, pendiente de resolver). "
                            "SHA-256 %s, %d bytes."
                            % (hashlib.sha256(data).hexdigest(), len(data))) from exc
    else:
        text = data
    stripped = text.strip()
    if stripped.startswith("\ufeff"):
        stripped = stripped[1:].strip()
    if not stripped:
        raise FileError("EMPTY", "El archivo está vacío.")
    if stripped.startswith("{"):
        doc = _json(stripped.encode("utf-8"))
        return _decode_values(doc)
    if _is_stgcm(stripped):
        last_error = None
        for prefix, key in (("STGCM3.VC.", KEY_CONFIG3), ("STGCM2.VC.", KEY_CONFIG2)):
            if stripped.startswith(prefix):
                try:
                    plain = _decrypt_envelope(stripped, prefix, key)
                    return _decode_values(_json(plain))
                except DecodeError as exc:
                    last_error = exc
        if last_error is not None:
            raise FileError("DECRYPT_FAILED", str(last_error))
    # Cualquier otro contenido: casi seguro un .vcv exportado por la app
    # (salida de nEncryptUserConfig), cuyo sobre no se resolvió offline.
    digest = hashlib.sha256(text.encode("utf-8")).hexdigest()
    raise FileError(
        "VCV_PENDING",
        "El archivo no es un sobre STGCM ni un JSON: parece un .vcv "
        "(TekProtect.nEncryptUserConfig, sobre no resuelto offline). "
        "SHA-256 %s, %d bytes. Para completarlo hace falta una muestra "
        "real de .vcv exportada por la app." % (digest, len(text.encode("utf-8"))))


def run(file_bytes) -> str | None:
    """API offline: JSON del archivo o None; nunca un perfil inventado."""
    try:
        return json.dumps(decode(file_bytes), ensure_ascii=False, indent=2,
                          allow_nan=False) + "\n"
    except (FileError, DecodeError):
        return None


def _self_test():
    """Round-trip .tgv sintético + catálogo real como .tgv + detección .vcv."""
    profile = {
        "version": "1.4",
        "Servers": [{"Name": "VC VPN Test", "Category": "PREMIUM",
                     "SSHPort": "22", "UDPDetails": "edd.com#edd#edd"}],
        "Tweaks": [{"Name": "VC VPN Test", "Mode": 6}],
    }
    plain = json.dumps(profile, ensure_ascii=False).encode("utf-8")
    blob3 = _encrypt_envelope(plain, "STGCM3.VC.", KEY_CONFIG3)
    doc = decode(blob3.encode("utf-8"))
    assert doc["Servers"][0]["Name"] == "VC VPN Test", doc
    assert doc["Servers"][0]["UDPDetails"] == "edd.com#edd#edd", doc
    blob2 = _encrypt_envelope(plain, "STGCM2.VC.", KEY_CONFIG2)
    doc2 = decode(blob2.encode("utf-8"))
    assert doc2["Tweaks"][0]["Mode"] == 6, doc2
    # El cuerpo real del catálogo en vivo sirve como .tgv de prueba.
    with open("catalog_sample.b64", "rb") as fh:
        live = decode(fh.read())
    assert live["version"] == "1.4", live.get("version")
    assert len(live["Servers"]) == 19, len(live["Servers"])
    assert len(live["Tweaks"]) == 634, len(live["Tweaks"])
    # Un .vcv (texto que no abre) se reporta, no se inventa.
    try:
        decode(b"VCUSERCFG-esto-no-es-un-sobre-STGCM")
    except FileError as exc:
        assert exc.code == "VCV_PENDING", exc.code
    else:
        raise AssertionError("un .vcv debería reportar VCV_PENDING")
    return ("self-test OK: round-trip .tgv STGCM3/STGCM2, catálogo real "
            "como .tgv (v1.4, 19 servidores, 634 tweaks), .vcv -> VCV_PENDING")


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Decodificador de archivos de VC VPN (com.vc.vpn): .tgv y .vcv.")
    parser.add_argument("--file", default=None,
                        help="Lee el archivo local (.tgv, .vcv o JSON).")
    parser.add_argument("--stdin", action="store_true",
                        help="Lee el archivo desde la entrada estándar.")
    parser.add_argument("--self-test", action="store_true",
                        help="Verifica el decodificador con datos sintéticos y reales.")
    parser.add_argument("-o", "--output", default=None,
                        help="Guarda el JSON descifrado en este archivo.")
    args = parser.parse_args(argv)

    if args.self_test:
        print(_self_test())
        return 0
    try:
        if args.file:
            with open(args.file, "rb") as fh:
                raw = fh.read()
        elif args.stdin:
            raw = sys.stdin.buffer.read()
        else:
            parser.error("usa --file, --stdin o --self-test")
            return 2
        out = run(raw)
        if out is None:
            # Re-ejecuta para el mensaje de error exacto.
            decode(raw)
    except FileError as exc:
        print("error [%s]: %s" % (exc.code, exc), file=sys.stderr)
        return 1
    except DecodeError as exc:
        print("error [%s]: %s" % (exc.code, exc), file=sys.stderr)
        return 1
    except Exception as exc:
        print("error: %s" % exc, file=sys.stderr)
        return 1
    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(out)
        print("guardado en %s" % args.output)
    else:
        sys.stdout.write(out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

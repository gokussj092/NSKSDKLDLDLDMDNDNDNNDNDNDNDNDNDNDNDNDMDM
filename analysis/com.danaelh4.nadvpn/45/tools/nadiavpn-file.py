#!/usr/bin/env python3
"""Decodificador de archivos .nad (NadiaVPN 1.4.6).

Uso:
    python3 nadiavpn-file.py perfil.nad
    python3 nadiavpn-file.py --password 'clave' perfil-protegido.nad

Lee un archivo .nad exportado por la app (texto con prefijo
NADIA_SEC_V2: o NADIA_SEC_PW2: seguido de Base64 del sobre
binario salt[16] || iv[16] || mac[32] || ciphertext), lo descifra
con el mismo esquema que nad://sec2: (PBKDF2-HMAC-SHA256 +
AES-256-CBC + HMAC-SHA256) e imprime el perfil en JSON.

El contenido en claro es un java.util.Properties serializado como
XML ("NadiaVPN Hardened Profile V2"); se convierte a JSON.

Variantes NADIA_SEC_HWID: / NADIA_SEC_HWID_PW: (perfil bloqueado
a HWID) no se pueden descifrar sin el HWID del dispositivo
autorizado; el script lo detecta y lo indica.

Sin soporte para .sks (su ruta de parseo no se localizo en el APK).
"""

import argparse
import base64
import json
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

import importlib.util

_spec = importlib.util.spec_from_file_location(
    "nadiavpn_text", Path(__file__).resolve().parent / "nadiavpn-text.py"
)
_mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_mod)
_decrypt_v2 = _mod._decrypt_v2


def _parse_properties_xml(data: bytes) -> dict:
    text = data.decode("utf-8")
    root = ET.fromstring(text)
    out = {}
    for entry in root.iter("entry"):
        key = entry.get("key")
        if key is not None:
            out[key] = entry.text if entry.text is not None else ""
    return out


def decode_file(path: Path, password=None) -> dict:
    raw = path.read_bytes()
    try:
        text = raw.decode("utf-8").strip()
    except UnicodeDecodeError:
        text = None
    if text is not None and text.startswith("NADIA_SEC_V2:"):
        blob = base64.b64decode(text[len("NADIA_SEC_V2:"):])
        return _parse_properties_xml(_decrypt_v2(blob))
    if text is not None and text.startswith("NADIA_SEC_PW2:"):
        if password is None:
            raise ValueError(
                "el archivo requiere contrasena (usa --password)"
            )
        blob = base64.b64decode(text[len("NADIA_SEC_PW2:"):])
        return _parse_properties_xml(_decrypt_v2(blob, password))
    if text is not None and (
        text.startswith("NADIA_SEC_HWID:")
        or text.startswith("NADIA_SEC_HWID_PW:")
    ):
        raise ValueError(
            "perfil bloqueado a HWID: se necesita el HWID del "
            "dispositivo autorizado (SHA-256 del android_id)"
        )
    if text is not None and (
        text.startswith("NADIA_SEC_V1:") or text.startswith("NADIA_SEC_PW:")
    ):
        raise ValueError(
            "formato legacy V1 (DES/ECB obsoleto o derivacion legacy): "
            "la app misma lo rechaza; vuelve a exportar el perfil"
        )
    # Sin prefijo: sobre binario directo salt||iv||mac||ciphertext.
    if len(raw) >= 80:
        try:
            return _parse_properties_xml(_decrypt_v2(raw))
        except ValueError:
            pass
    raise ValueError(
        "archivo no reconocido (se espera .nad con prefijo "
        "NADIA_SEC_V2: / NADIA_SEC_PW2: o sobre binario directo)"
    )


def main():
    ap = argparse.ArgumentParser(
        description="Decodifica archivos .nad de NadiaVPN"
    )
    ap.add_argument("file", help="archivo .nad")
    ap.add_argument(
        "--password", default=None, help="contrasena para NADIA_SEC_PW2:"
    )
    args = ap.parse_args()
    try:
        obj = decode_file(Path(args.file), args.password)
    except Exception as e:
        print("error: %s" % e, file=sys.stderr)
        return 1
    print(json.dumps(obj, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())

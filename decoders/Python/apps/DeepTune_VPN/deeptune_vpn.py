#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
DeepTune-VPN (tun.deep.vpn) - Decodificador de archivos de configuracion.

Decodifica los archivos propios de DeepTune-VPN:
  - configfile.json del APK (activo en la app): base64 cifrado con la
    contrasena AuraNETXRPTeam (misma construccion que los campos).
  - deep3.txt descargado (catalogo en vivo): se descarta el byte en el
    indice 3 y se descifra con la contrasena
    XjLn/DGiA0EpZFaLCd9gsGA6YDCBgxnl.
  - Un JSON ya descifrado: solo descifra los campos que sigan cifrados.

La app tambien importa enlaces estandar VLESS/VMess/trojan/ss y JSON de
configuracion Sandok; esos ya los decodifica SP-DECODE y no necesitan
este script. DeepTune-VPN no tiene extension de archivo propia ni
esquema de enlace propio.

Metodo (extraido del APK v8, libgojni.so - AndroidLibXrayLite):
  Layout: base64(salt[0:16] || nonce[16:28] || ciphertext[28:])
  Argon2id (t=3, m=8192 KiB, p=1, keyLen=32) + AES-256-GCM, AAD = salt.
  Los campos dentro del JSON usan la misma construccion. Si un valor no
  descifra con ninguna contrasena, es texto plano y se deja como esta
  (igual que la app).

Uso:
    python3 deeptune_vpn.py <archivo> [-o salida.json]

Sin -o, imprime el JSON descifrado en stdout. El resumen va a stderr.
Requiere: argon2-cffi, cryptography.
"""

import argparse
import base64
import json
import sys

from argon2.low_level import Type, hash_secret_raw
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

FILE_PASSWORD = b"XjLn/DGiA0EpZFaLCd9gsGA6YDCBgxnl"   # deep3.txt (catalogo en vivo)
FIELD_PASSWORD = b"AuraNETXRPTeam"                    # configfile.json y campos
PASSWORDS = (FIELD_PASSWORD, FILE_PASSWORD)

SERVER_FIELDS = [
    "ServerHost", "ServerAddress", "OVPNUser", "OVPNPass", "SSH_Host",
    "SSH_User", "SSH_Pass", "CustomCertificate", "SlowDNSHost", "SlowDNSKey",
    "V2rayUUID", "V2rayAddress", "V2rayHost", "V2raySNI", "V2rayConfig",
    "V2rayPath", "TrojanPass",
]
NETWORK_FIELDS = [
    "Payload", "SNI", "V2rayConfig", "V2rayAddress", "V2rayHost", "V2raySNI",
]


def argon2_key(password, salt):
    return hash_secret_raw(
        secret=password, salt=salt,
        time_cost=3, memory_cost=8192, parallelism=1,
        hash_len=32, type=Type.ID,
    )


def aes_gcm_decrypt(raw, password):
    """raw = salt[0:16] || nonce[16:28] || ciphertext[28:], AAD = salt."""
    salt, nonce, ct = raw[:16], raw[16:28], raw[28:]
    key = argon2_key(password, salt)
    return AESGCM(key).decrypt(nonce, ct, salt)


def decrypt_field(value):
    """Descifra un campo; si no descifra, es texto plano y se deja como esta."""
    if not value:
        return value
    try:
        raw = base64.b64decode(value.strip())
    except Exception:
        return value
    for password in PASSWORDS:
        try:
            return aes_gcm_decrypt(raw, password).decode("utf-8")
        except Exception:
            continue
    return value


def decrypt_catalog(data):
    for server in data.get("Servers") or []:
        for field in SERVER_FIELDS:
            if server.get(field):
                server[field] = decrypt_field(server[field])
    for network in data.get("Networks") or []:
        for field in NETWORK_FIELDS:
            if network.get(field):
                network[field] = decrypt_field(network[field])
    return data


def decode_file(text):
    """Detecta el formato y devuelve el JSON de configuracion descifrado."""
    body = text.strip()
    if body.startswith("{"):
        return json.loads(body)          # JSON ya descifrado
    # configfile.json: base64 directo, contrasena de campos.
    try:
        raw = base64.b64decode(body)
        return json.loads(aes_gcm_decrypt(raw, FIELD_PASSWORD).decode("utf-8"))
    except Exception:
        pass
    # deep3.txt: se descarta el byte en el indice 3, contrasena de archivo.
    try:
        raw = base64.b64decode(body[:3] + body[4:])
        return json.loads(aes_gcm_decrypt(raw, FILE_PASSWORD).decode("utf-8"))
    except Exception:
        pass
    raise ValueError("No se pudo descifrar el archivo (formato no reconocido)")


def main():
    parser = argparse.ArgumentParser(
        description="Decodifica un archivo de configuracion de DeepTune-VPN."
    )
    parser.add_argument("archivo", help="configfile.json, deep3.txt o JSON")
    parser.add_argument("-o", "--output", help="Archivo JSON de salida")
    args = parser.parse_args()

    try:
        with open(args.archivo, "r", encoding="utf-8", errors="replace") as fh:
            text = fh.read()
    except OSError as exc:
        print("Error leyendo el archivo: %s" % exc, file=sys.stderr)
        return 1

    try:
        data = decrypt_catalog(decode_file(text))
    except Exception as exc:
        print("Error descifrando el archivo: %s" % exc, file=sys.stderr)
        return 1

    out = json.dumps(data, ensure_ascii=False, indent=2)
    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(out)
    else:
        sys.stdout.write(out + "\n")

    print(
        "DeepTune-VPN v%s: %d servidores, %d redes"
        % (
            data.get("Version"),
            len(data.get("Servers") or []),
            len(data.get("Networks") or []),
        ),
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())

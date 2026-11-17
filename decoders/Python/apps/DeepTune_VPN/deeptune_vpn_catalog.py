#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
DeepTune-VPN (tun.deep.vpn) - Descargador y descifrador del catalogo en vivo.

Descarga el catalogo (deep3.txt) con la misma peticion que hace la app
y lo descifra por completo. El resultado es SOLO el catalogo (datos),
sin ninguna API de descarga dentro del JSON.

Metodo (extraido del APK v8, libgojni.so - AndroidLibXrayLite):
  Archivo en vivo:
    - GET https://strongteam.co/api/deeptune/deep3.txt
      header: User-Agent: DeepTune-VPN
    - Se descarta el byte en el indice 3 del texto, luego base64.
    - Layout: base64(salt[0:16] || nonce[16:28] || ciphertext[28:])
      Argon2id (t=3, m=8192 KiB, p=1, keyLen=32) + AES-256-GCM, AAD = salt.
    - Contrasena del archivo en vivo: XjLn/DGiA0EpZFaLCd9gsGA6YDCBgxnl
  Campos dentro del JSON:
    - Misma construccion (Argon2id + AES-256-GCM, AAD = salt), contrasena
      AuraNETXRPTeam. Si un valor no descifra con ninguna de las dos
      contrasenas, es texto plano y se deja como esta (igual que la app).

Uso:
    python3 deeptune_vpn_catalog.py [-o salida.json]

Sin -o, imprime el JSON del catalogo en stdout. El resumen va a stderr.
Requiere: argon2-cffi, cryptography. Descarga con requests si esta
disponible (la respuesta de Cloudflare se trunca con urllib), con
respaldo a urllib; reintenta la descarga si el descifrado falla
(una descarga truncada no pasa la verificacion AES-GCM).
"""

import argparse
import base64
import json
import sys
import time
import urllib.request

from argon2.low_level import Type, hash_secret_raw
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

CATALOG_URL = "https://strongteam.co/api/deeptune/deep3.txt"
USER_AGENT = "DeepTune-VPN"

FILE_PASSWORD = b"XjLn/DGiA0EpZFaLCd9gsGA6YDCBgxnl"   # archivo en vivo (deep3.txt)
FIELD_PASSWORD = b"AuraNETXRPTeam"                    # campos dentro del JSON
PASSWORDS = (FIELD_PASSWORD, FILE_PASSWORD)

# Campos que pueden venir cifrados (el resto es texto plano o numeros).
SERVER_FIELDS = [
    "ServerHost", "ServerAddress", "OVPNUser", "OVPNPass", "SSH_Host",
    "SSH_User", "SSH_Pass", "CustomCertificate", "SlowDNSHost", "SlowDNSKey",
    "V2rayUUID", "V2rayAddress", "V2rayHost", "V2raySNI", "V2rayConfig",
    "V2rayPath", "TrojanPass",
    # Coordinator 2026-11-17: verified live — these 4 fields decrypt with
    # the existing passwords but were missing from the list, so the result
    # left them encrypted. ServerIPHost -> hostname; UDP_obfs/UDP_user/
    # H2pass -> one Base64 token layer (legitimate plaintext for keys).
    "ServerIPHost", "UDP_obfs", "UDP_user", "H2pass",
]
NETWORK_FIELDS = [
    "Payload", "SNI", "V2rayConfig", "V2rayAddress", "V2rayHost", "V2raySNI",
    # Coordinator 2026-11-17: verified live — BugDNS decrypts to 8.8.8.8
    # with the existing passwords in 24/102 networks; was missing here.
    "BugDNS",
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


def decrypt_file_text(text):
    """Descifra el contenido de deep3.txt: descarta el byte 3 y descifra."""
    body = text.strip()
    body = body[:3] + body[4:]          # la app descarta el byte en el indice 3
    raw = base64.b64decode(body)
    return aes_gcm_decrypt(raw, FILE_PASSWORD).decode("utf-8")


def decrypt_field(value):
    """Descifra un campo del catalogo; si no descifra, es texto plano."""
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


def download_catalog():
    """Descarga deep3.txt. Cloudflare trunca la respuesta con urllib
    (IncompleteRead), asi que se usa requests cuando esta disponible y
    urllib solo como respaldo; reintenta hasta 3 veces por transporte."""
    last_error = None
    try:
        import requests

        for _ in range(3):
            try:
                response = requests.get(
                    CATALOG_URL,
                    headers={"User-Agent": USER_AGENT},
                    timeout=60,
                )
                response.raise_for_status()
                return response.text
            except Exception as exc:  # noqa: BLE001 - reintento
                last_error = exc
                time.sleep(1)
    except ImportError:
        pass
    for _ in range(3):
        try:
            request = urllib.request.Request(
                CATALOG_URL, headers={"User-Agent": USER_AGENT}
            )
            with urllib.request.urlopen(request, timeout=60) as response:
                return response.read().decode("utf-8", "replace")
        except Exception as exc:  # noqa: BLE001 - reintento
            last_error = exc
            time.sleep(1)
    raise last_error


def main():
    parser = argparse.ArgumentParser(
        description="Descarga y descifra el catalogo en vivo de DeepTune-VPN."
    )
    parser.add_argument("-o", "--output", help="Archivo JSON de salida")
    args = parser.parse_args()

    data = None
    last_error = None
    for _ in range(3):
        try:
            text = download_catalog()
        except Exception as exc:
            print("Error descargando el catalogo: %s" % exc, file=sys.stderr)
            return 1
        try:
            data = json.loads(decrypt_file_text(text))
            break
        except Exception as exc:
            # Descarga truncada o corrupta (no pasa AES-GCM): reintentar.
            last_error = exc
            data = None
    if data is None:
        print("Error descifrando el catalogo: %s" % last_error, file=sys.stderr)
        return 1

    data = decrypt_catalog(data)
    out = json.dumps(data, ensure_ascii=False, indent=2)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(out)
    else:
        sys.stdout.write(out + "\n")

    print(
        "Catalogo DeepTune-VPN v%s: %d servidores, %d redes"
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

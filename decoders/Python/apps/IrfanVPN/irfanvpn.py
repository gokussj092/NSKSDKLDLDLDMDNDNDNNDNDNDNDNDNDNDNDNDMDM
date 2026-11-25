#!/usr/bin/env python3
"""Decodificador de IRFAN VPN (Irfan V3, build 7) para SP-DECODE.

Paquete: com.jxgtm.stronghold. Fork de v2rayNG + servicios de tunel
Sandok/Ultra (SSH/OVPN/SlowDNS/Hysteria). Catalogo en vivo
VERIFIED_REAL (version 2.8, 3 servidores, 63 networks) descargado de
strongteam.co y descifrado con la construccion de la app
(ver ANALISIS.md).

Camino de descifrado (libgojni.so, Go AndroidLibXrayLite, verificado
con la etiqueta GCM):
  base64(salt[0:16] | nonce[16:28] | ct+tag[28:])
  clave = Argon2id(t=3, m=8192 KiB, p=1, hash_len=32)
  AES-256-GCM, AAD = salt.
  Dos contrasenas:
    DO / eo (campos y config incluido):  "NewDecryptLibPassword"   (21)
    decrypt / Encrypt (en vivo y .irfan): "NewDecryptLibPasswordII" (23)

Flujos:
  * Config incluido (assets/configfile.json): sobre DO, contrasena I.
  * Catalogo vivo (GET https://strongteam.co/api/irfan/irfan1.txt,
    User-Agent: IRFAN VPN): sobre decrypt, contrasena II. La app
    guarda el fresco como pref KidConfig7 y compara Version.
  * Campos por valor (host, usuario, SNI, payload, ...): sobre DO,
    contrasena I. Los literales ("[host]", "", puertos) se dejan tal
    cual: DO falla y la app conserva el valor original.
  * Archivo .irfan (exportar/importar una NetworkList):
    Encrypt/decrypt con contrasena II. La importacion pasa por
    Libv2ray.parseConfig -> decrypt (II); gc() re-cifra con EO (I).
    VERIFIED_SYNTHETIC: sin muestra real .irfan; el --self-test hace
    round-trip sintetico. Falta un .irfan real exportado para
    VERIFIED_REAL.

Uso (venv ~/workspace/http-custom-update/venv/bin/python;
argon2-cffi y pycryptodome):
    python3 irfanvpn.py --download [--out catalog.json]
        Descarga el catalogo vivo, lo descifra (sobre II) y descifra
        todos los campos (I). Guarda el JSON completo descifrado.
    python3 irfanvpn.py --decrypt-bundled FILE
        Descifra assets/configfile.json (sobre I) + campos.
    python3 irfanvpn.py --decrypt-file FILE.irfan
        Descifra un archivo .irfan (sobre II) -> JSON NetworkList.
    python3 irfanvpn.py --encrypt-irfan '{"Name": ...}'
        Cifra una NetworkList JSON a formato .irfan (sintetico).
    python3 irfanvpn.py --self-test
        Round-trip sintetico: sobre I, sobre II y .irfan.
"""

import argparse
import base64
import json
import sys
import urllib.request

from argon2.low_level import hash_secret_raw, Type
from Crypto.Cipher import AES

# ---------------------------------------------------------------------------
# Constantes del metodo (claves del METODO de la app, no credenciales de
# servidor: sin ellas el descifrado es imposible, como en otros
# decodificadores del repo).
# ---------------------------------------------------------------------------

CATALOG_URL = "https://strongteam.co/api/irfan/irfan1.txt"
USER_AGENT = "IRFAN VPN"          # Go CU(): header User-Agent exacto
REQUEST_TIMEOUT_S = 15

PASSWORD_I = "NewDecryptLibPassword"     # DO / EO (campos, config incluido)
PASSWORD_II = "NewDecryptLibPasswordII"  # decrypt / Encrypt (vivo, .irfan)

ARGON2_TIME = 3
ARGON2_MEMORY_KIB = 8192
ARGON2_PARALLELISM = 1
ARGON2_HASH_LEN = 32


# ---------------------------------------------------------------------------
# Primitivas (equivalentes a DO/decrypt/Encrypt/EO de AndroidLibXrayLite)
# ---------------------------------------------------------------------------

def _derive_key(password, salt):
    return hash_secret_raw(
        password.encode("utf-8"), salt,
        time_cost=ARGON2_TIME, memory_cost=ARGON2_MEMORY_KIB,
        parallelism=ARGON2_PARALLELISM, hash_len=ARGON2_HASH_LEN,
        type=Type.ID)


def decrypt_blob(b64_text, password):
    """base64(salt16|nonce12|ct+tag16) -> bytes en claro.

    Levanta ValueError si el formato es corto o la etiqueta GCM no
    verifica (contrasena incorrecta o datos corruptos).
    """
    raw = base64.b64decode(b64_text, validate=True)
    if len(raw) < 28 + 16:
        raise ValueError("ciphertext too short: %d bytes" % len(raw))
    salt, nonce, ct_tag = raw[:16], raw[16:28], raw[28:]
    key = _derive_key(password, salt)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    cipher.update(salt)  # AAD = salt
    return cipher.decrypt_and_verify(ct_tag[:-16], ct_tag[-16:])


def encrypt_blob(plain_bytes, password):
    """Inversa de decrypt_blob (solo para --self-test / .irfan).

    Sal y nonce aleatorios (crypto/rand en Go); salida
    base64(salt|nonce|ct+tag).
    """
    import os
    salt = os.urandom(16)
    nonce = os.urandom(12)
    key = _derive_key(password, salt)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    cipher.update(salt)  # AAD = salt
    ct, tag = cipher.encrypt_and_digest(plain_bytes)
    return base64.b64encode(salt + nonce + ct + tag).decode("ascii")


def decrypt_field(value, password=PASSWORD_I):
    """Descifra un valor de campo con DO (contrasena I).

    La app conserva el valor original cuando DO falla (literal como
    "[host]", "", "443", "sandok"): mismo comportamiento aqui.
    """
    if not isinstance(value, str) or value == "":
        return value
    try:
        return decrypt_blob(value, password).decode("utf-8")
    except Exception:
        return value


# ---------------------------------------------------------------------------
# Catalogo (ConfigData: Servers[] + Networks[])
# ---------------------------------------------------------------------------

def decrypt_catalog(obj):
    """Descifra todos los valores de campo de un ConfigData ya abierto.

    Recorre recursivamente todos los strings y aplica decrypt_field
    (contrasena I). Los literales pasan intactos.
    """
    if isinstance(obj, dict):
        return {k: decrypt_catalog(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [decrypt_catalog(v) for v in obj]
    if isinstance(obj, str):
        return decrypt_field(obj)
    return obj


def decrypt_envelope(b64_text, password):
    """Sobre completo (config incluido o catalogo vivo) -> objeto JSON."""
    return json.loads(decrypt_blob(b64_text, password).decode("utf-8"))


def download_catalog_raw(timeout=REQUEST_TIMEOUT_S, retries=3):
    """GET exacto de la app: sin query, User-Agent: IRFAN VPN.

    Reintenta hasta 3 veces: la respuesta va en chunked y la conexion
    puede cortarse a mitad (IncompleteRead visto en vivo con
    urllib). Si urllib falla en todos los intentos, usa curl con la
    misma peticion exacta (GET + mismo User-Agent), que completa la
    descarga donde urllib se corta.
    """
    import http.client
    import subprocess
    import time
    last = None
    for attempt in range(1, retries + 1):
        try:
            req = urllib.request.Request(CATALOG_URL, method="GET")
            req.add_header("User-Agent", USER_AGENT)
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                if resp.status != 200:
                    raise RuntimeError("HTTP %d al descargar el catalogo" % resp.status)
                return resp.read().decode("utf-8")
        except (http.client.IncompleteRead, ConnectionError, TimeoutError) as e:
            last = e
            if attempt < retries:
                time.sleep(2 * attempt)
    try:
        p = subprocess.run(
            ["curl", "-sS", "-A", USER_AGENT, "--max-time", str(timeout),
             CATALOG_URL],
            capture_output=True, timeout=timeout + 10, check=True)
        return p.stdout.decode("utf-8")
    except Exception as e:
        raise RuntimeError(
            "descarga incompleta tras %d intentos urllib (%s) y curl (%s)"
            % (retries, last, e))


def download_catalog(timeout=REQUEST_TIMEOUT_S):
    """Descarga + descifra el catalogo vivo. Devuelve (objeto JSON,
    cuerpo_cifrado). Verificado en vivo: HTTP 200, 83.752 B cifrados
    -> JSON v2.8, 3 servidores, 63 networks."""
    raw = download_catalog_raw(timeout=timeout)
    plain = decrypt_envelope(raw.strip(), PASSWORD_II)
    return decrypt_catalog(plain), raw


# ---------------------------------------------------------------------------
# Archivo .irfan (una NetworkList JSON, contrasena II)
# ---------------------------------------------------------------------------

def decrypt_irfan_file(path):
    with open(path, encoding="utf-8") as f:
        content = f.read().strip()
    return json.loads(decrypt_blob(content, PASSWORD_II).decode("utf-8"))


def encrypt_irfan(network_json):
    """NetworkList (dict o JSON str) -> contenido de archivo .irfan."""
    if isinstance(network_json, dict):
        network_json = json.dumps(network_json, ensure_ascii=False)
    return encrypt_blob(network_json.encode("utf-8"), PASSWORD_II)


# ---------------------------------------------------------------------------
# Self-test (todo sintetico; no usa red ni el APK)
# ---------------------------------------------------------------------------

def self_test():
    sample = {"Name": "SelfTest", "TunnelType": "V2ray",
              "Payload": "GET http://example.com/ HTTP/1.1[crlf]Host: [host][crlf]",
              "SNI": "www.example.com", "V2rayAddress": "[host]"}
    plain = json.dumps(sample, ensure_ascii=False)
    # (a) Sobre I (DO/EO): campos y config incluido.
    enc_i = encrypt_blob(plain.encode("utf-8"), PASSWORD_I)
    dec_i = decrypt_blob(enc_i, PASSWORD_I).decode("utf-8")
    assert json.loads(dec_i) == sample, "round-trip sobre I"
    try:
        decrypt_blob(enc_i, PASSWORD_II)
        raise AssertionError("II no debio descifrar el sobre I")
    except ValueError:
        pass
    # (b) Sobre II (decrypt/Encrypt): vivo y .irfan.
    enc_ii = encrypt_blob(plain.encode("utf-8"), PASSWORD_II)
    dec_ii = decrypt_blob(enc_ii, PASSWORD_II).decode("utf-8")
    assert json.loads(dec_ii) == sample, "round-trip sobre II"
    try:
        decrypt_blob(enc_ii, PASSWORD_I)
        raise AssertionError("I no debio descifrar el sobre II")
    except ValueError:
        pass
    # (c) Archivo .irfan: cifrar + descifrar (sintetico).
    irfan = encrypt_irfan(sample)
    assert decrypt_blob(irfan, PASSWORD_II).decode("utf-8") == plain
    # (d) Campo literal pasa intacto; campo cifrado se abre.
    assert decrypt_field("[host]") == "[host]"
    assert decrypt_field("") == ""
    assert decrypt_field(encrypt_blob(b"www.pubgmobile.com", PASSWORD_I)) \
        == "www.pubgmobile.com"
    print("OK self-test: sobre I (DO/EO), sobre II (decrypt/Encrypt), "
          ".irfan y campos -> round-trip VERIFIED_SYNTHETIC")
    print("Archivo .irfan: falta una muestra real exportada para "
          "VERIFIED_REAL.")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--download", action="store_true",
                    help="descarga el catalogo vivo y lo descifra")
    ap.add_argument("--out", default="catalog.json",
                    help="destino del JSON descifrado (def: catalog.json)")
    ap.add_argument("--save-encrypted", action="store_true",
                    help="guarda tambien el cuerpo cifrado como <out>.enc")
    ap.add_argument("--decrypt-bundled", metavar="FILE",
                    help="descifra assets/configfile.json (sobre I)")
    ap.add_argument("--decrypt-file", metavar="FILE.irfan",
                    help="descifra un archivo .irfan (sobre II)")
    ap.add_argument("--encrypt-irfan", metavar="JSON",
                    help="cifra una NetworkList JSON a formato .irfan")
    ap.add_argument("--self-test", action="store_true",
                    help="round-trip sintetico (sobres I/II, .irfan)")
    args = ap.parse_args(argv)

    if args.self_test:
        self_test()
        return 0
    if args.download:
        obj, raw = download_catalog()
        with open(args.out, "w", encoding="utf-8") as f:
            json.dump(obj, f, ensure_ascii=False, indent=2)
            f.write("\n")
        if args.save_encrypted:
            with open(args.out + ".enc", "w", encoding="utf-8") as f:
                f.write(raw)
        print("OK: catalogo v%s, %d servidores, %d networks -> %s"
              % (obj.get("Version"), len(obj.get("Servers", [])),
                 len(obj.get("Networks", [])), args.out))
        return 0
    if args.decrypt_bundled:
        with open(args.decrypt_bundled, encoding="utf-8") as f:
            obj = decrypt_envelope(f.read().strip(), PASSWORD_I)
        obj = decrypt_catalog(obj)
        print(json.dumps(obj, ensure_ascii=False, indent=2))
        return 0
    if args.decrypt_file:
        obj = decrypt_irfan_file(args.decrypt_file)
        print(json.dumps(obj, ensure_ascii=False, indent=2))
        return 0
    if args.encrypt_irfan:
        print(encrypt_irfan(args.encrypt_irfan))
        return 0
    ap.print_help()
    return 2


if __name__ == "__main__":
    sys.exit(main())

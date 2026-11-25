#!/usr/bin/env python3
"""Decodificador de Ways Tunnel 18 (build 18) para SP-DECODE.

Paquete: com.ways.tunnel. Motor multi-engine (SocksHttp/Xray/OpenVPN/
dnstt/Farik UDP). Catalogo en vivo VERIFIED_REAL (version 1.0.49,
5 servidores, 78 networks/payloads) descargado de GitHub y descifrado
con la construccion de la app (ver ANALISIS.md).

Camino de descifrado del config (clase Java Ltn2, verificado contra el
asset real y contra el catalogo vivo):
  1. 640 glifos -> pares nibble segun el alfabeto de Ltn2 (indice =
     valor del nibble) -> 320 bytes de texto Base64.
  2. Base64 -> AES-256-CBC cifrado.
  3. Clave: SHA-256 del HEX EN MAYUSCULAS de la contrasena
     (NativeUtils.g1() = "dam0n" para el config).
  4. IV: 16 bytes a cero. Cifrado: AES/CBC/PKCS7PADDING
     (NativeUtils.g4()). Relleno PKCS7.

Tweaks wyst:// (VERIFIED_SYNTHETIC, ver nota abajo):
  La app descifra el tweak pegado con NativeUtils.g2() = "tweakdam0n",
  mismo AES/CBC con IV cero (Ltn2.e() -> Ltn2.d() -> Cipher), y lo
  parsea como JSONObject. La codificacion exacta del texto tras
  "wyst://" NO esta verificada con una muestra real: este script
  CANONIZA Base64(cifrado AES-CBC PKCS7 del JSON) al cifrar, y al
  descifrar prueba en orden Base64, glifos (mismo camino del config)
  y hexadecimal. El --self-test hace round-trip SINTETICO; falta una
  muestra real wyst:// para VERIFIED_REAL. No afirmes que un tweak
  real abre sin probarlo.

Premium: NO hay catalogo premium separado verificable. En el catalogo
vivo 1.0.49 no existe ningun campo VIP/premium (0 menciones de
"vip"/"premium" en todo el JSON; los 5 servidores tienen Flag 'ma';
las networks usan Flag = codigo de pais) y la app solo descarga este
unico config.json. Por eso NO existe download_premium_catalog() en
este script: la funcion premium queda como "sin catalogo premium
separado verificable". La app si tiene Play Billing + asset govip.webp
("Go VIP") + tweaks por HWID, pero eso es pago en la app, no un
segundo endpoint de catalogo. Ver ANALISIS.md, seccion Premium.

La funcion nativa decode() de libways-native.so (XOR de un byte) NO
interviene en este camino; se incluye como native_decode() solo para
completitud (ver native-report.md).

Uso (venv ~/workspace/http-custom-update/venv/bin/python;
`cryptography` disponible; sin ella se usa `openssl` CLI):
    python3 waystunnel.py --download [--out catalog.json]
        Descarga el catalogo vivo (GET + ?t=<millis>, timeout 15 s),
        lo descifra y guarda el JSON. Tambien guarda el cuerpo
        cifrado junto al destino como <dest>.enc si se pide con
        --save-encrypted.
    python3 waystunnel.py --decrypt-config <config.json cifrado>
        Descifra un config.json cifrado local (asset o remoto).
    python3 waystunnel.py --decrypt-tweak 'wyst://...'
        Descifra un enlace de tweak.
    python3 waystunnel.py --encrypt-tweak '{"Name": ...}'
        Cifra un JSON de tweak y emite el enlace wyst:// (sintetico).
    python3 waystunnel.py --self-test
        Round-trip sintetico del config (glifos) y del tweak (Base64).
"""

import argparse
import base64
import hashlib
import json
import sys
import time
import urllib.request

# ---------------------------------------------------------------------------
# Constantes del metodo (claves del METODO de la app, no credenciales de
# servidor: sin ellas el descifrado es imposible, como en otros
# decodificadores del repo).
# ---------------------------------------------------------------------------

CATALOG_URL = ("https://raw.githubusercontent.com/waystunnel/politicas/"
               "refs/heads/main/config.json")
REQUEST_TIMEOUT_S = 15  # Lau2.doInBackground: timeouts de 15.000 ms

ALPHABET = "ۦᜑᜐᜏᜎᜌᜈᜇᜆᜂᜁᜀᜋᜊᜉᜅᜄ"
GLYPH_TO_NIBBLE = {ch: i for i, ch in enumerate(ALPHABET)}

PASSWORD_CONFIG = "dam0n"       # NativeUtils.g1() -> config (asset y remoto)
PASSWORD_TWEAK = "tweakdam0n"   # NativeUtils.g2() -> tweaks wyst://
CIPHER = "AES/CBC/PKCS7PADDING"    # NativeUtils.g4()
DIGEST = "SHA-256"                 # NativeUtils.g5()
ZERO_IV = bytes(16)                # Ltn2.a


# ---------------------------------------------------------------------------
# Primitivas (equivalentes a Ltn2.a/b/c/d/e)
# ---------------------------------------------------------------------------

def glyphs_to_bytes(text):
    """640 glifos -> 320 bytes (pares alto/bajo)."""
    if len(text) % 2 != 0:
        raise ValueError("longitud impar: %d glifos" % len(text))
    out = bytearray()
    for i in range(0, len(text), 2):
        hi = GLYPH_TO_NIBBLE.get(text[i])
        lo = GLYPH_TO_NIBBLE.get(text[i + 1])
        if hi is None or lo is None:
            raise ValueError("glifo fuera del alfabeto en posicion %d" % i)
        if hi > 15 or lo > 15:
            raise ValueError("glifo con indice >15 en posicion %d" % i)
        out.append(((hi << 4) | lo) & 0xFF)
    return bytes(out)


def bytes_to_glyphs(data):
    """Inversa de glyphs_to_bytes (solo para --self-test / cifrado)."""
    out = []
    for b in data:
        out.append(ALPHABET[(b >> 4) & 0xF])
        out.append(ALPHABET[b & 0xF])
    return "".join(out)


def derive_key(password):
    """Ltn2.e() + Ltn2.d(): SHA-256(hex_mayusculas(password))."""
    hexed = password.encode("utf-8").hex().upper()
    return hashlib.sha256(hexed.encode("utf-8")).digest()


def _aes_cbc_decrypt(ciphertext, key, iv=ZERO_IV):
    try:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        from cryptography.hazmat.primitives.padding import PKCS7
        dec = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
        padded = dec.update(ciphertext) + dec.finalize()
        unpadder = PKCS7(128).unpadder()
        return unpadder.update(padded) + unpadder.finalize()
    except ImportError:
        pass
    import subprocess
    p = subprocess.run(
        ["openssl", "enc", "-d", "-aes-256-cbc", "-K", key.hex(),
         "-iv", iv.hex(), "-nopad"],
        input=ciphertext, capture_output=True, check=True)
    padded = p.stdout
    pad = padded[-1]
    if not 1 <= pad <= 16 or padded[-pad:] != bytes([pad]) * pad:
        raise ValueError("relleno PKCS7 invalido")
    return padded[:-pad]


def _aes_cbc_encrypt(plaintext, key, iv=ZERO_IV):
    try:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        from cryptography.hazmat.primitives.padding import PKCS7
        padder = PKCS7(128).padder()
        padded = padder.update(plaintext) + padder.finalize()
        enc = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
        return enc.update(padded) + enc.finalize()
    except ImportError:
        pass
    import subprocess
    pad = 16 - (len(plaintext) % 16)
    padded = plaintext + bytes([pad]) * pad
    p = subprocess.run(
        ["openssl", "enc", "-aes-256-cbc", "-K", key.hex(),
         "-iv", iv.hex(), "-nopad"],
        input=padded, capture_output=True, check=True)
    return p.stdout


def native_decode(data, key_byte):
    """Equivalente Python de libways-native.so:decode() (XOR 1 byte).

    NO se usa para el config.json ni para los tweaks (ver docstring
    del modulo); se incluye para completitud.
    """
    return bytes(b ^ key_byte for b in data)


# ---------------------------------------------------------------------------
# Config (asset y remoto): glifos -> Base64 -> AES-CBC
# ---------------------------------------------------------------------------

def decode_config(glyph_text, password=PASSWORD_CONFIG):
    """Cadena de glifos -> JSON en claro (str). Equivalente a Ltn2.a()."""
    b64_bytes = glyphs_to_bytes(glyph_text)
    b64_text = b64_bytes.decode("utf-8")          # texto Base64
    ciphertext = base64.b64decode(b64_text)       # Base64.decode(NO_WRAP)
    key = derive_key(password)
    plain = _aes_cbc_decrypt(ciphertext, key)
    return plain.decode("utf-8")


def encode_config(plain_text, password=PASSWORD_CONFIG):
    """Inversa de decode_config (solo para --self-test)."""
    key = derive_key(password)
    ciphertext = _aes_cbc_encrypt(plain_text.encode("utf-8"), key)
    return bytes_to_glyphs(base64.b64encode(ciphertext))


def decode_config_file(path, password=PASSWORD_CONFIG):
    with open(path, encoding="utf-8") as f:
        return decode_config(f.read().strip(), password)


# ---------------------------------------------------------------------------
# Descarga en vivo del catalogo (misma peticion exacta que la app)
# ---------------------------------------------------------------------------

def download_catalog_raw(timeout=REQUEST_TIMEOUT_S):
    """GET <CATALOG_URL>?t=<millis>, timeout 15 s. Devuelve el cuerpo
    cifrado (texto de glifos). Equivalente a Lau2.doInBackground."""
    url = "%s?t=%d" % (CATALOG_URL, int(time.time() * 1000))
    req = urllib.request.Request(url, method="GET")
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        if resp.status != 200:
            raise RuntimeError("HTTP %d al descargar el catalogo" % resp.status)
        return resp.read().decode("utf-8")


def download_catalog(timeout=REQUEST_TIMEOUT_S):
    """Descarga + descifra el catalogo vivo. Devuelve (objeto JSON,
    cuerpo_cifrado). Verificado en vivo: HTTP 200, 276.225 B cifrados
    -> 36.007 B JSON (SHA-256 468725bbef20019fbd48d84b0029e5912ee30df8
    518b428413b5202305aa7b10), version 1.0.49."""
    raw = download_catalog_raw(timeout=timeout)
    plain = decode_config(raw.strip(), PASSWORD_CONFIG)
    return json.loads(plain), raw


# ---------------------------------------------------------------------------
# Tweaks wyst:// (VERIFIED_SYNTHETIC: sin muestra real)
# ---------------------------------------------------------------------------

TWEAK_SCHEME = "wyst://"


def encrypt_tweak(plain_text, password=PASSWORD_TWEAK):
    """JSON de tweak -> enlace wyst:// (construccion canonica Base64).

    SINTETICO: la construccion AES/CBC/IV-cero con g2 esta
    reconstruida del DEX, pero la codificacion del texto tras
    "wyst://" no esta verificada con una muestra real.
    """
    key = derive_key(password)
    ciphertext = _aes_cbc_encrypt(plain_text.encode("utf-8"), key)
    return TWEAK_SCHEME + base64.b64encode(ciphertext).decode("ascii")


def decrypt_tweak(link, password=PASSWORD_TWEAK):
    """Enlace wyst:// -> JSON en claro (str).

    Prueba en orden: Base64 (canonico), glifos (camino del config),
    hexadecimal. Si ninguna produce relleno PKCS7 valido, falla.
    """
    if not link.startswith(TWEAK_SCHEME):
        raise ValueError("el enlace debe empezar por %s" % TWEAK_SCHEME)
    payload = link[len(TWEAK_SCHEME):].strip()
    key = derive_key(password)
    errors = []

    def try_bytes(ciphertext):
        return _aes_cbc_decrypt(ciphertext, key).decode("utf-8")

    # 1. Base64 (canonico).
    try:
        return try_bytes(base64.b64decode(payload))
    except Exception as e:  # noqa: BLE001 - se prueban otras codificaciones
        errors.append("base64: %s" % e)
    # 2. Glifos (mismo camino que el config).
    try:
        b64_bytes = glyphs_to_bytes(payload)
        return try_bytes(base64.b64decode(b64_bytes.decode("utf-8")))
    except Exception as e:  # noqa: BLE001
        errors.append("glifos: %s" % e)
    # 3. Hexadecimal.
    try:
        return try_bytes(bytes.fromhex(payload))
    except Exception as e:  # noqa: BLE001
        errors.append("hex: %s" % e)
    raise ValueError("no se pudo descifrar el tweak (%s)" % "; ".join(errors))


# ---------------------------------------------------------------------------
# Self-test (todo sintetico; no usa red ni el APK)
# ---------------------------------------------------------------------------

def self_test():
    sample = {"Name": "SelfTest", "Modo": "ssl_ssh",
              "Payload": "CONNECT [host_port] [protocol][crlf]",
              "SNI": "example.com"}
    plain = json.dumps(sample, ensure_ascii=False)
    # (a) Config: glifos -> Base64 -> AES, round-trip con g1.
    enc = encode_config(plain, PASSWORD_CONFIG)
    assert len(enc) == 640 or len(enc) % 2 == 0, "longitud de glifos"
    dec = decode_config(enc, PASSWORD_CONFIG)
    assert json.loads(dec) == sample, "round-trip config"
    # Contrasena incorrecta debe fallar (relleno invalido).
    try:
        decode_config(enc, PASSWORD_TWEAK)
        raise AssertionError("g2 no debio descifrar el config")
    except ValueError:
        pass
    # (b) Tweak: Base64 -> AES, round-trip con g2.
    link = encrypt_tweak(plain, PASSWORD_TWEAK)
    assert link.startswith(TWEAK_SCHEME)
    dec2 = decrypt_tweak(link, PASSWORD_TWEAK)
    assert json.loads(dec2) == sample, "round-trip tweak"
    print("OK self-test: config (glifos, g1) y tweak (base64, g2) "
          "round-trip VERIFIED_SYNTHETIC")
    print("Tweak wyst://: falta una muestra real para VERIFIED_REAL.")


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
    ap.add_argument("--decrypt-config", metavar="FILE",
                    help="descifra un config.json cifrado local")
    ap.add_argument("--decrypt-tweak", metavar="LINK",
                    help="descifra un enlace wyst://")
    ap.add_argument("--encrypt-tweak", metavar="JSON",
                    help="cifra un JSON de tweak y emite wyst:// (sintetico)")
    ap.add_argument("--self-test", action="store_true",
                    help="round-trip sintetico (config + tweak)")
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
    if args.decrypt_config:
        plain = decode_config_file(args.decrypt_config)
        obj = json.loads(plain)
        print(json.dumps(obj, ensure_ascii=False, indent=2))
        return 0
    if args.decrypt_tweak:
        plain = decrypt_tweak(args.decrypt_tweak)
        obj = json.loads(plain)
        print(json.dumps(obj, ensure_ascii=False, indent=2))
        return 0
    if args.encrypt_tweak:
        print(encrypt_tweak(args.encrypt_tweak))
        return 0
    ap.print_help()
    return 2


if __name__ == "__main__":
    sys.exit(main())

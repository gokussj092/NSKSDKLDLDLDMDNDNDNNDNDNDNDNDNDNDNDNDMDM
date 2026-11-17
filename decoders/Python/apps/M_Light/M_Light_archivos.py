#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
M Light (com.pausatotal.mlight) 3.1.55 - decodificador de archivos .pausa
y enlaces pausa:// exportados por la app.

Metodo exacto (clase st, import st....(InputStream, password)):
  * El explorador de importar acepta extension "pausa" (o sin extension).
  * Import: lee todo el archivo como UTF-8 y hace trim. Intenta, en orden:
      (a) Base64-decode (NO_WRAP) -> AES/CBC descifrar con clave
          SHA-256(hex(password)), IV 16 ceros; si el resultado empieza
          por "{" es el texto plano.
      (b) AESCrypt.decrypt(password, texto_original): formato
          baybayin-hex (mismo esquema que el catalogo: pares baybayin
          -> Base64 -> AES/CBC, IV cero, clave SHA-256(hex(password))).
    Despues: si el texto empieza por "{" -> JSONObject -> Properties;
    si no -> java.util.Properties.load().
  * Export: construye java.util.Properties con los campos del perfil y
    hace Properties.store() -> AESCrypt.encrypt(password, texto) ->
    escribe la cadena baybayin-hex.
  * Enlace pausa:// (ConfigImportFileActivity): trim, quita el prefijo
    "pausa://" o "pausa:", corta en "?" (toma la parte antes del primer
    "?"), Uri.decode, y alimenta los bytes como stream de importacion.
    Es decir, el enlace lleva el contenido del archivo (URL-encoded).
  * La app valida al importar: file.blockHwid debe ser "1" o vacio.

ESTADO: NO VERIFICADO de extremo a extremo. No existe ningun archivo
.pausa real exportado por la app en un telefono. El round-trip sintetico
(cifrar un Properties de prueba y descifrarlo) si esta verificado con
--self-test. Un archivo real exportado por la app lo confirmaria.

Uso:
  python3 M_Light_archivos.py archivo.pausa [-o perfil.json]
  python3 M_Light_archivos.py --link "pausa://...." [-o perfil.json]
  python3 M_Light_archivos.py --encrypt perfil.json [-o archivo.pausa] [--format base64|baybayin]
  python3 M_Light_archivos.py --self-test
"""

import argparse
import base64
import binascii
import hashlib
import json
import os
import sys
import urllib.parse

# La contrasena de archivos sale de la app (StringFog/lsparanoid).
# Es distinta de la clave del catalogo. Solo vive en este script.
_FILE_PASSWORD = "dam9n@2024!P4ND4#"

ALPHABET = "".join(chr(c) for c in (
    0x6e6, 0x1711, 0x1710, 0x170f, 0x170e, 0x170c, 0x1708, 0x1707, 0x1706,
    0x1702, 0x1701, 0x1700, 0x170b, 0x170a, 0x1709, 0x1705, 0x1704))


class DecodeError(Exception):
    """Fallo al descifrar o parsear un archivo .pausa."""


# ------------------------------------------------------------------ AES
try:
    from Crypto.Cipher import AES as _PycryptAES  # type: ignore

    def _aes_cbc_decrypt(key, iv, data):
        return _PycryptAES.new(key, _PycryptAES.MODE_CBC, iv).decrypt(data)

    def _aes_cbc_encrypt(key, iv, data):
        return _PycryptAES.new(key, _PycryptAES.MODE_CBC, iv).encrypt(data)

    _AES_BACKEND = "pycryptodome"
except Exception:  # pragma: no cover - fallback puro (mismo que M_Light.py)
    _AES_BACKEND = "pure-python"
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    try:
        import M_Light as _ml
        _aes_cbc_decrypt = _ml._aes_cbc_decrypt
        _aes_cbc_encrypt = _ml._aes_cbc_encrypt
    except Exception as exc:  # noqa: BLE001
        raise ImportError("sin pycryptodome y sin M_Light.py para el fallback AES") from exc


def derive_key(password):
    """Clave AES-256: SHA-256 del hex en mayusculas de la clave en claro."""
    return hashlib.sha256(password.encode("utf-8").hex().upper().encode("ascii")).digest()


def _unpad(data):
    if not data:
        raise DecodeError("descifrado vacio")
    pad = data[-1]
    if pad < 1 or pad > 16 or data[-pad:] != bytes([pad]) * pad:
        raise DecodeError("padding PKCS7 invalido")
    return data[:-pad]


def _pad(data):
    pad = 16 - (len(data) % 16)
    return data + bytes([pad]) * pad


# ------------------------------------------------- codificacion baybayin
def baybayin_decode(text):
    text = "".join(text.split())
    if len(text) % 2:
        raise DecodeError("texto baybayin con longitud impar: %d" % len(text))
    idx = {c: i for i, c in enumerate(ALPHABET)}
    out = bytearray()
    for i in range(0, len(text), 2):
        hi = idx.get(text[i])
        lo = idx.get(text[i + 1])
        if hi is None or lo is None:
            raise DecodeError("caracter fuera del alfabeto en posicion %d" % i)
        out.append(hi * 16 + lo)
    return bytes(out)


def baybayin_encode(data):
    return "".join(ALPHABET[b >> 4] + ALPHABET[b & 0x0f] for b in data)


def _aes_decrypt_b64_or_raise(b64text, password):
    ciphertext = base64.b64decode(b64text, validate=False)
    key = derive_key(password)
    return _unpad(_aes_cbc_decrypt(key, b"\x00" * 16, ciphertext))


def decrypt_aescrypt(text, password=_FILE_PASSWORD):
    """Formato baybayin-hex: pares -> Base64 -> AES/CBC -> texto plano."""
    raw = baybayin_decode(text)
    try:
        b64 = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise DecodeError("bytes intermedios no son UTF-8") from exc
    key = derive_key(password)
    try:
        ciphertext = base64.b64decode(b64, validate=False)
    except Exception as exc:
        raise DecodeError("Base64 intermedia invalida") from exc
    return _unpad(_aes_cbc_decrypt(key, b"\x00" * 16, ciphertext)).decode("utf-8")


def encrypt_aescrypt(plaintext, password=_FILE_PASSWORD):
    """Texto plano -> cadena baybayin-hex (formato de exportacion)."""
    key = derive_key(password)
    ciphertext = _aes_cbc_encrypt(key, b"\x00" * 16, _pad(plaintext.encode("utf-8")))
    b64 = base64.b64encode(ciphertext).decode("ascii")
    return baybayin_encode(b64.encode("utf-8"))


# ------------------------------------------- formato java.util.Properties
def parse_properties(text):
    """Parser de java.util.Properties.load(): comentarios #/!, escapes
    \\uXXXX, \\t \\n \\r \\\\, continuaciones de linea con \\ final y
    separadores = : o espacios. Devuelve dict ordenado por aparicion."""
    props = {}
    lines = text.splitlines()
    buf = ""
    for raw_line in lines:
        line = raw_line
        if buf:
            line = buf + line.lstrip()
            buf = ""
        # continuacion: numero impar de '\' al final
        bs = 0
        for ch in reversed(line):
            if ch == "\\":
                bs += 1
            else:
                break
        if bs % 2 == 1:
            buf = line[:-1]
            continue
        stripped = line.lstrip()
        if not stripped or stripped[0] in ("#", "!"):
            continue
        # separa clave/valor
        i = 0
        n = len(line)
        while i < n and line[i] not in (" ", "\t", "=", ":"):
            if line[i] == "\\" and i + 1 < n:
                i += 2
            else:
                i += 1
        key = line[:i]
        j = i
        while j < n and line[j] in (" ", "\t"):
            j += 1
        if j < n and line[j] in ("=", ":"):
            j += 1
            while j < n and line[j] in (" ", "\t"):
                j += 1
        value = line[j:]
        props[_unescape(key.strip())] = _unescape(value.strip())
    return props


def _unescape(s):
    out = []
    i = 0
    while i < len(s):
        c = s[i]
        if c != "\\" or i + 1 >= len(s):
            out.append(c)
            i += 1
            continue
        nxt = s[i + 1]
        if nxt == "u":
            try:
                v = int(s[i + 2:i + 6], 16)
            except ValueError:
                out.append(nxt)
                i += 2
                continue
            # par sustituto (codepoints > U+FFFF, p. ej. emojis): Java
            # escribe \ud83c\uddf2; se combinan en un solo caracter.
            if 0xd800 <= v <= 0xdbff and s[i + 6:i + 8] == "\\u":
                try:
                    w = int(s[i + 8:i + 12], 16)
                except ValueError:
                    w = 0
                if 0xdc00 <= w <= 0xdfff:
                    out.append(chr(0x10000 + ((v - 0xd800) << 10) + (w - 0xdc00)))
                    i += 12
                    continue
            out.append(chr(v))
            i += 6
            continue
        mapping = {"t": "\t", "n": "\n", "r": "\r", "f": "\f"}
        out.append(mapping.get(nxt, nxt))
        i += 2
    return "".join(out)


def _escape_store(s, is_key=False):
    out = []
    for ch in s:
        o = ord(ch)
        if ch == "\\":
            out.append("\\\\")
        elif ch == "\t":
            out.append("\\t")
        elif ch == "\n":
            out.append("\\n")
        elif ch == "\r":
            out.append("\\r")
        elif ch == "\f":
            out.append("\\f")
        elif is_key and ch in (" ", "=", ":"):
            out.append("\\" + ch)
        elif o < 0x20 or o > 0x7e:
            if o > 0xffff:  # par sustituto, como java.util.Properties.store
                o -= 0x10000
                out.append("\\u%04x\\u%04x" % (0xd800 + (o >> 10), 0xdc00 + (o & 0x3ff)))
            else:
                out.append("\\u%04x" % o)
        else:
            out.append(ch)
    return "".join(out)


def serialize_properties(props):
    """Formato de java.util.Properties.store() con comentario null:
    primera linea '#<fecha>' y luego clave=valor con escapes."""
    import email.utils
    import time
    date = email.utils.formatdate(time.time(), usegmt=False)
    lines = ["#" + date]
    for key, value in props.items():
        lines.append("%s=%s" % (_escape_store(str(key), True), _escape_store(str(value))))
    return "\n".join(lines) + "\n"


# ------------------------------------------------------- decodificacion
def decrypt_file_text(text, password=_FILE_PASSWORD):
    """Texto de un archivo .pausa -> dict del perfil (o texto plano si no
    es JSON ni Properties). Replica el orden de intentos de la app."""
    text = text.strip()
    if not text:
        raise DecodeError("archivo vacio")
    plain = None
    errors = []
    # (a) Base64 -> AES
    try:
        raw = base64.b64decode(text, validate=False)
        if raw:
            plain = _unpad(_aes_cbc_decrypt(derive_key(password), b"\x00" * 16, raw)).decode("utf-8")
    except (binascii.Error, ValueError, UnicodeDecodeError) as exc:
        errors.append("base64: %s" % exc)
    # (b) AESCrypt baybayin-hex
    if plain is None:
        try:
            plain = decrypt_aescrypt(text, password)
        except Exception as exc:  # noqa: BLE001
            errors.append("baybayin: %s" % exc)
    if plain is None:
        raise DecodeError("ningun formato abrio con la contrasena (%s)" % "; ".join(errors))
    plain = plain.strip()
    if plain.startswith("{"):
        try:
            obj = json.loads(plain)
        except json.JSONDecodeError as exc:
            raise DecodeError("JSON invalido tras descifrar: %s" % exc) from exc
        if isinstance(obj, dict):
            return {str(k): ("" if v is None else str(v)) for k, v in obj.items()}
        return obj
    props = parse_properties(plain)
    if props:
        return props
    return {"_texto": plain}


def decrypt_file(path, password=_FILE_PASSWORD):
    with open(path, encoding="utf-8", errors="strict") as fh:
        return decrypt_file_text(fh.read(), password)


def decrypt_link(link, password=_FILE_PASSWORD):
    """Enlace pausa://... -> dict del perfil. La app: trim, quita el
    prefijo pausa:// o pausa:, corta en '?', Uri.decode."""
    text = link.strip()
    if text.startswith("pausa://"):
        text = text[len("pausa://"):]
    elif text.startswith("pausa:"):
        text = text[len("pausa:"):]
    else:
        raise DecodeError("el enlace no empieza por pausa:// ni pausa:")
    text = text.split("?", 1)[0]
    text = urllib.parse.unquote(text)
    return decrypt_file_text(text, password)


def encrypt_file_text(props, password=_FILE_PASSWORD, fmt="baybayin"):
    """dict de perfil -> texto cifrado listo para guardar como .pausa.
    fmt=baybayin: formato de exportacion de la app (Properties.store +
    AESCrypt). fmt=base64: Base64 del AES (el otro formato que acepta
    la importacion)."""
    if isinstance(props, dict):
        plain = serialize_properties(props)
    else:
        plain = str(props)
    if fmt == "baybayin":
        return encrypt_aescrypt(plain, password)
    if fmt == "base64":
        key = derive_key(password)
        ciphertext = _aes_cbc_encrypt(key, b"\x00" * 16, _pad(plain.encode("utf-8")))
        return base64.b64encode(ciphertext).decode("ascii")
    raise ValueError("fmt debe ser baybayin o base64")


# -------------------------------------------------------------- self-test
def _self_test():
    checks = []

    def check(name, fn):
        try:
            fn()
            checks.append((name, True, ""))
        except Exception as exc:  # noqa: BLE001
            checks.append((name, False, "%s: %s" % (type(exc).__name__, exc)))

    sample = {
        "Name": "Prueba 🇲🇽",
        "ServerIP": "203.0.113.7",
        "ServerUser": "usuario",
        "ServerPass": "p@ss w0rd",
        "Payload": "GET / HTTP/1.1\r\nHost: ejemplo.com\r\n",
        "file.blockHwid": "1",
        "ZacDevzS": "true",
    }

    def _roundtrip_baybayin():
        enc = encrypt_file_text(sample, fmt="baybayin")
        if any(c not in ALPHABET for c in enc):
            raise AssertionError("el cifrado no usa solo el alfabeto")
        back = decrypt_file_text(enc)
        if back != sample:
            raise AssertionError("round-trip baybayin difiere: %r" % back)

    def _roundtrip_base64():
        enc = encrypt_file_text(sample, fmt="base64")
        back = decrypt_file_text(enc)
        if back != sample:
            raise AssertionError("round-trip base64 difiere: %r" % back)

    def _roundtrip_json():
        plain = json.dumps(sample, ensure_ascii=False)
        enc = encrypt_aescrypt(plain)
        back = decrypt_file_text(enc)
        if back != sample:
            raise AssertionError("round-trip JSON difiere: %r" % back)

    def _roundtrip_link():
        enc = encrypt_file_text(sample, fmt="baybayin")
        link = "pausa://" + urllib.parse.quote(enc, safe="") + "?x=1"
        back = decrypt_link(link)
        if back != sample:
            raise AssertionError("round-trip pausa:// difiere: %r" % back)

    def _properties_parser():
        text = "#Sun Nov 15 13:00:00 PST 2026\nName=Prueba \\u00e9\\u00f1\nkey\\:con\\:dos\\:puntos=valor\\ttab\n# comentario\n! otro\nvacio=\n"
        props = parse_properties(text)
        if props.get("Name") != "Prueba éñ":
            raise AssertionError("escape \\uXXXX fallo: %r" % props)
        if props.get("key:con:dos:puntos") != "valor\ttab":
            raise AssertionError("escapes de clave/valor fallaron: %r" % props)
        if props.get("vacio") != "":
            raise AssertionError("valor vacio fallo: %r" % props)

    def _wrong_password_fails():
        enc = encrypt_file_text(sample, fmt="baybayin")
        try:
            decrypt_file_text(enc, password="clave-incorrecta")
        except DecodeError:
            return
        raise AssertionError("descifro con contrasena incorrecta")

    check("round-trip .pausa baybayin (export app)", _roundtrip_baybayin)
    check("round-trip .pausa base64", _roundtrip_base64)
    check("round-trip JSON plano cifrado", _roundtrip_json)
    check("round-trip enlace pausa://", _roundtrip_link)
    check("parser java.util.Properties (escapes)", _properties_parser)
    check("contrasena incorrecta rechaza", _wrong_password_fails)

    failed = [c for c in checks if not c[1]]
    for name, ok, err in checks:
        print(("OK  " if ok else "FAIL") + " " + name + ((" - " + err) if err else ""))
    print("SELF-TEST: %d/%d OK" % (len(checks) - len(failed), len(checks)))
    return 0 if not failed else 1


# -------------------------------------------------------------------- CLI
def main(argv=None):
    ap = argparse.ArgumentParser(
        description="M Light 3.1.55 - decodificador de archivos .pausa y enlaces pausa://.")
    src = ap.add_mutually_exclusive_group()
    src.add_argument("file", nargs="?", help="archivo .pausa a descifrar")
    src.add_argument("--link", metavar="ENLACE",
                     help='enlace pausa://... a descifrar')
    src.add_argument("--encrypt", metavar="ARCHIVO",
                     help="cifrar un perfil JSON o Properties a .pausa")
    ap.add_argument("--format", choices=["baybayin", "base64"], default="baybayin",
                    help="formato de salida al cifrar (por defecto: baybayin, el de la app)")
    ap.add_argument("-o", "--output", metavar="ARCHIVO",
                    help="guardar el resultado en ARCHIVO (por defecto: stdout)")
    ap.add_argument("--self-test", action="store_true",
                    help="pruebas internas (round-trip sintetico, sin red)")
    args = ap.parse_args(argv)

    if args.self_test:
        return _self_test()

    if args.encrypt:
        with open(args.encrypt, encoding="utf-8") as fh:
            raw = fh.read()
        try:
            props = json.loads(raw)
            if not isinstance(props, dict):
                raise ValueError("el JSON debe ser un objeto")
        except (json.JSONDecodeError, ValueError):
            props = parse_properties(raw)
        out = encrypt_file_text(props, fmt=args.format)
        result = out
    elif args.link:
        result = json.dumps(decrypt_link(args.link), ensure_ascii=False, indent=2)
    elif args.file:
        result = json.dumps(decrypt_file(args.file), ensure_ascii=False, indent=2)
    else:
        ap.error("indica un archivo .pausa, --link o --encrypt")

    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(result + ("\n" if not result.endswith("\n") else ""))
        print("guardado en %s" % args.output)
    else:
        print(result)
    return 0


if __name__ == "__main__":
    sys.exit(main())

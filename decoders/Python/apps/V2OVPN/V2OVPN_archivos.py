#!/usr/bin/env python3
"""V2OVPN 2.2.3 (com.v2rayservice.v2ovpn): archivos de configuracion locales.

Standalone Python 3.10+, solo biblioteca estandar, sin acceso a red.
Para el catalogo usar V2OVPN.py. El descifrador Tink vive en V2OVPN.py
(misma carpeta); este script lo importa para no duplicar la cripto.

Formatos (MainActivity.onCreate, Lm11, Lvc1, OpenVPNService):

  * profile.json — el catalogo guardado en getFilesDir() tras la
    descarga, con una SEGUNDA capa (verificada contra las clases de la
    propia app en la JVM: Li61.g = Base64, Li61.h = XXTEA):
      flujo Tink StreamingAead (mismo que el catalogo) -> cadena
      Base64 -> XXTEA modificado (delta 0x2E0BA747, clave = primeros
      16 B UTF-8 de MainDetail.b() = "aZ%RU%itRMB^8&Ue", longitud
      como palabra extra) -> JSON con nombres ANTIGUOS.
    La app migra los nombres al importarlo y luego lo guarda como
    profile.enc y BORRA profile.json. Migracion (MainActivity.onCreate,
    verificada clave por clave contra er2.p):
      nivel superior: "Profiles" -> "Networks" (si no hay "Networks")
      Servers: Name -> ServerName; Flag -> ServerFlag;
        SSLPort -> OpenVPNSSLPort Y SSHSSLPort (mismo valor en ambas);
        si falta ServerDNS, ServerDNS = ServerIP;
        OvpnCertificate -> setOpenVPN;
        AutoLogIn / MultiCert: booleano -> cadena "true"/"false"
      Networks: Name -> PayloadName; Flag -> PayloadFlag;
        Info -> PayloadInfo; si falta ServerDNS, ServerDNS = "";
        UseDefProxy: booleano -> cadena
    Si el texto plano del flujo Tink ya es JSON limpio (el cuerpo
    crudo del catalogo, sin la segunda capa), se devuelve tal cual
    sin aplicar la capa XXTEA: asi el mismo decode() abre tanto un
    profile.json real como el cuerpo descargado.
  * profile.enc — otro flujo Tink (Lm11: lo lee con un StreamingAead
    de un keyset Tink construido en la app, no con la clave fija del
    catalogo). NO se puede abrir sin el dispositivo: la clave vive en
    el keyset de la app. Este script lo detecta por el nombre y lo
    informa como pendiente, sin inventar un descifrado.
  * config.json (Lvc1) y proxies.json (OpenVPNService) — JSON plano
    que la app GENERA (config v2ray y lista de proxies); no son
    archivos de importacion. Si se pasan, se devuelven tal cual.

No hay archivos .sks: la app no tiene soporte .sks. Los .ovpn son
texto plano y SP-DECODE ya los cubre; la app no declara intent-filter
VIEW para archivos en el manifiesto (no hay asociacion de extension),
asi que no hay formato propio de archivo exportable mas alla de
profile.json / profile.enc.
"""
from __future__ import annotations

import argparse
import base64
import binascii
import json
import struct
import sys
from pathlib import Path

MAX_BYTES = 8 * 1024 * 1024

sys.path.insert(0, str(Path(__file__).resolve().parent))
try:
    from V2OVPN import DecodeError, _open_fields, decode as _decode_catalog
    from V2OVPN import decrypt_stream, encrypt_stream
except ImportError as exc:  # pragma: no cover
    raise SystemExit("V2OVPN_archivos.py needs V2OVPN.py in the same folder.") from exc

# Blob de 128 caracteres de MainDetail.b() (libapi-v2ovpn.so, mismo
# que en RoVPN); la clave XXTEA son sus primeros 16 B UTF-8.
MAINDETAIL_B = (
    "aZ%RU%itRMB^8&UeF3HkNFpTGA&sxv&qN$ZmP6Yh@EDJmtpd2%cwrYcq5HsV@rVGs75Xhvyz9uaLm"
    "USeP^hAovJLXRusF$%dQo2sCHkUmmJB@s*L2FA7v!*zHP@oQov%")
XXTEA_KEY = MAINDETAIL_B.encode("utf-8")[:16]
XXTEA_DELTA = 772515655  # 0x2E0BA747
_M32 = 0xFFFFFFFF


# ---------------------------------------------------------------- XXTEA modificado (Li61.h / Li61.v)

def _mx(sum_, y, z, p, e, k):
    return ((((z >> 5) ^ (y << 2)) + ((y >> 3) ^ (z << 4)))
            ^ ((sum_ ^ y) + (k[(p & 3) ^ e] ^ z))) & _M32


def _to_words(data):
    n = (len(data) + 3) // 4
    v = [0] * n
    for i, b in enumerate(data):
        v[i >> 2] |= b << ((i & 3) << 3)
    return v


def _to_bytes(v, length):
    out = bytearray()
    for i in range(length):
        out.append((v[i >> 2] >> ((i & 3) << 3)) & 0xFF)
    return bytes(out)


def xxtea_encrypt(data, key=XXTEA_KEY):
    """XXTEA modificado (Li61.h inverso): longitud como palabra extra."""
    v = _to_words(data) + [len(data)]
    k = _to_words(key[:16].ljust(16, b"\x00"))
    n = len(v)
    if n < 2:
        return data
    rounds = 6 + 52 // n
    sum_ = 0
    z, y = v[n - 1], v[0]
    for _ in range(rounds):
        sum_ = (sum_ + XXTEA_DELTA) & _M32
        e = (sum_ >> 2) & 3
        for p in range(n - 1):
            y = v[p + 1]
            z = v[p] = (v[p] + _mx(sum_, y, z, p, e, k)) & _M32
        y = v[0]
        z = v[n - 1] = (v[n - 1] + _mx(sum_, y, z, n - 1, e, k)) & _M32
    return _to_bytes(v, n * 4)


def xxtea_decrypt(data, key=XXTEA_KEY):
    """XXTEA modificado (Li61.h): devuelve el texto plano o None."""
    v = _to_words(data)
    k = _to_words(key[:16].ljust(16, b"\x00"))
    n = len(v)
    if n < 2:
        return None
    rounds = 6 + 52 // n
    sum_ = (rounds * XXTEA_DELTA) & _M32
    y, z = v[0], v[n - 1]
    for _ in range(rounds):
        e = (sum_ >> 2) & 3
        for p in range(n - 1, 0, -1):
            z = v[p - 1]
            y = v[p] = (v[p] - _mx(sum_, y, z, p, e, k)) & _M32
        z = v[n - 1]
        y = v[0] = (v[0] - _mx(sum_, y, z, 0, e, k)) & _M32
        sum_ = (sum_ - XXTEA_DELTA) & _M32
    length = v[n - 1]
    if length < n * 4 - 7 or length > n * 4 - 4:
        return None
    return _to_bytes(v, length)


# ---------------------------------------------------------------- migracion de nombres antiguos

def _rename(obj, old, new):
    if old in obj:
        obj[new] = obj.pop(old)


def _bool_to_str(obj, key):
    if isinstance(obj.get(key), bool):
        obj[key] = "true" if obj[key] else "false"


def migrate(doc):
    """Migra un JSON de profile.json con nombres antiguos al formato
    actual del catalogo (MainActivity.onCreate). No toca los campos
    ED: (los abre _open_fields despues)."""
    if not isinstance(doc, dict):
        return doc
    if "Profiles" in doc and "Networks" not in doc:
        doc["Networks"] = doc.pop("Profiles")
    for server in doc.get("Servers", []) or []:
        if not isinstance(server, dict):
            continue
        _rename(server, "Name", "ServerName")
        _rename(server, "Flag", "ServerFlag")
        if "SSLPort" in server:
            server["OpenVPNSSLPort"] = server["SSLPort"]
            server["SSHSSLPort"] = server["SSLPort"]
            del server["SSLPort"]
        if "ServerDNS" not in server and "ServerIP" in server:
            server["ServerDNS"] = server["ServerIP"]
        _rename(server, "OvpnCertificate", "setOpenVPN")
        _bool_to_str(server, "AutoLogIn")
        _bool_to_str(server, "MultiCert")
    for network in doc.get("Networks", []) or []:
        if not isinstance(network, dict):
            continue
        _rename(network, "Name", "PayloadName")
        _rename(network, "Flag", "PayloadFlag")
        _rename(network, "Info", "PayloadInfo")
        if "ServerDNS" not in network:
            network["ServerDNS"] = ""
        _bool_to_str(network, "UseDefProxy")
    return doc


# ---------------------------------------------------------------- decode principal

def decode_profile_json(data):
    """Descifra un profile.json real: Tink -> Base64 -> XXTEA -> JSON
    con nombres antiguos -> migracion. Devuelve el dict con los campos
    ED: ya abiertos. Si el texto plano del flujo Tink ya es JSON
    limpio (cuerpo crudo del catalogo), lo devuelve sin la capa XXTEA."""
    # 1. Flujo Tink (Base64 o bytes del flujo).
    try:
        plain = decrypt_stream(_stream_bytes(data))
    except DecodeError:
        # Si no es un flujo Tink, quiza sea JSON plano.
        return _decode_plain(data)
    text = plain.decode("utf-8", "replace").strip()
    if text.startswith("{"):
        try:
            doc = json.loads(text)
        except json.JSONDecodeError:
            doc = None
        if isinstance(doc, dict) and "Servers" in doc:
            return _open_fields(doc)
    # 2. Segunda capa: Base64 -> XXTEA -> JSON con nombres antiguos.
    try:
        cipher = base64.b64decode(text + "=" * (-len(text) % 4), validate=False)
    except (ValueError, binascii.Error) as exc:
        raise DecodeError("FORMAT_ERROR",
                          "El texto plano del flujo Tink no es JSON ni Base64.") from exc
    inner = xxtea_decrypt(cipher)
    if inner is None:
        raise DecodeError("FORMAT_ERROR",
                          "La capa XXTEA de profile.json no abre con la clave de MainDetail.b().")
    try:
        doc = json.loads(inner.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise DecodeError("FORMAT_ERROR",
                          "El interior XXTEA de profile.json no es JSON.") from exc
    if not isinstance(doc, dict) or "Servers" not in doc:
        raise DecodeError("FORMAT_ERROR",
                          "El interior XXTEA de profile.json no es un catalogo.")
    return _open_fields(migrate(doc))


def _stream_bytes(data):
    """Acepta el cuerpo Base64 (texto o bytes) o los bytes del flujo y
    devuelve los bytes del flujo Tink."""
    import re
    if isinstance(data, str):
        raw = data.encode("utf-8", "replace")
    else:
        raw = bytes(data)
    if len(raw) > MAX_BYTES:
        raise DecodeError("SIZE_LIMIT", "La entrada supera el limite de tamano.")
    compact = re.sub(rb"[ \t\r\n]", b"", raw)
    if compact:
        try:
            cand = base64.b64decode(compact + b"=" * (-len(compact) % 4), validate=True)
        except (ValueError, binascii.Error):
            cand = None
        if cand is not None and len(cand) >= 40 and 8 <= cand[0] <= 64:
            return cand
    if len(raw) >= 40 and 8 <= raw[0] <= 64:
        return raw
    raise DecodeError("FORMAT_ERROR",
                      "Se esperaba el cuerpo Base64 del catalogo o el flujo Tink.")


def _decode_plain(data):
    """JSON plano (config.json generado por la app, o un profile.json
    ya descifrado): se devuelve tal cual, con migracion si trae
    nombres antiguos."""
    text = data.decode("utf-8-sig") if isinstance(data, bytes) else data
    stripped = text.strip()
    if not stripped.startswith("{"):
        raise DecodeError("FORMAT_ERROR", "El archivo no es JSON ni un flujo Tink.")
    try:
        doc = json.loads(stripped)
    except json.JSONDecodeError as exc:
        raise DecodeError("FORMAT_ERROR", "JSON invalido.") from exc
    if not isinstance(doc, dict) or "Servers" not in doc:
        raise DecodeError("FORMAT_ERROR", "El JSON no es un catalogo V2OVPN.")
    return _open_fields(migrate(doc))


def decode(data, filename=None):
    """Decodifica un archivo local de V2OVPN y devuelve el dict.

    filename (opcional) es el nombre del archivo: si es profile.enc se
    informa como no descifrable sin el dispositivo; profile.json se
    abre con la doble capa Tink+XXTEA; JSON plano pasa tal cual (con
    migracion si trae nombres antiguos)."""
    name = (filename or "").lower()
    if "profile.enc" in name or name.endswith(".enc"):
        raise DecodeError(
            "PROFILE_ENC_KEY",
            "profile.enc usa un flujo Tink con una clave del keyset de "
            "la app (Lm11), no la clave fija del catalogo. Solo se "
            "puede abrir en el dispositivo que lo genero; hace falta "
            "una captura en vivo o el keyset exportado.")
    return decode_profile_json(data)


def run(file_bytes):
    """Devuelve el archivo decodificado como JSON (texto)."""
    doc = decode(file_bytes)
    return json.dumps(doc, ensure_ascii=False, indent=2, allow_nan=False) + "\n"


def _read(path):
    with Path(path).open("rb") as stream:
        data = stream.read(MAX_BYTES + 1)
    if len(data) > MAX_BYTES:
        raise DecodeError("SIZE_LIMIT", "El archivo supera el limite de tamano.")
    return data


def _self_test():
    """Verifica el descifrado de profile.json con un archivo sintetico
    de doble capa (Tink+Base64+XXTEA, nombres antiguos) construido
    aqui mismo, con la muestra real del catalogo (sin segunda capa) y
    que profile.enc se informe como pendiente."""
    checks = {}
    # 1. profile.json sintetico de doble capa, con nombres antiguos.
    old = {
        "Version": "46.1", "Message": " Up",
        "Servers": [
            {"Name": "TEST SERVER", "Flag": "th", "SSLPort": "1194",
             "ServerIP": "ED:MQYS44TPOZYG4LTVNM======",
             "OvpnCertificate": "ED:ORSXG5A=",
             "AutoLogIn": True, "MultiCert": False}
        ],
        "Profiles": [
            {"Name": "TEST PAYLOAD", "Flag": "", "Info": "nota",
             "UseDefProxy": False, "Payload": "ED:ORSXG5A="}
        ],
    }
    plain_old = json.dumps(old, ensure_ascii=False).encode("utf-8")
    xxtea_ct = xxtea_encrypt(plain_old)
    checks["xxtea_roundtrip"] = xxtea_decrypt(xxtea_ct) == plain_old
    b64_layer = base64.b64encode(xxtea_ct).decode("ascii")
    stream = encrypt_stream(b64_layer.encode("ascii"),
                            header_salt=bytes(range(32)),
                            nonce_prefix=bytes.fromhex("01020304050607"))
    profile_b64 = base64.b64encode(stream).decode("ascii")
    doc = decode(profile_b64, filename="profile.json")
    srv = doc["Servers"][0]
    net = doc["Networks"][0]
    checks["profile_json_version"] = doc.get("Version") == "46.1"
    checks["profile_json_server_name"] = srv.get("ServerName") == "TEST SERVER"
    checks["profile_json_server_flag"] = srv.get("ServerFlag") == "th"
    checks["profile_json_ssl_ports"] = (
        srv.get("OpenVPNSSLPort") == "1194" and srv.get("SSHSSLPort") == "1194")
    checks["profile_json_server_dns_default"] = srv.get("ServerDNS") == "d1.rovpn.uk"
    checks["profile_json_set_openvpn"] = srv.get("setOpenVPN") == "test"
    checks["profile_json_bool_to_str"] = (
        srv.get("AutoLogIn") == "true" and srv.get("MultiCert") == "false")
    checks["profile_json_network_name"] = net.get("PayloadName") == "TEST PAYLOAD"
    checks["profile_json_network_info"] = net.get("PayloadInfo") == "nota"
    checks["profile_json_network_dns_default"] = net.get("ServerDNS") == ""
    checks["profile_json_network_proxy_str"] = net.get("UseDefProxy") == "false"
    # 2. Muestra real del catalogo (cuerpo crudo, sin segunda capa).
    sample_path = Path(__file__).with_name("catalog_sample.b64")
    if sample_path.exists():
        doc2 = decode(_read(sample_path), filename="profile.json")
        checks["profile_json_sample_version"] = doc2.get("Version") == "46.1"
        checks["profile_json_sample_servers"] = len(doc2.get("Servers", [])) == 12
        checks["profile_json_sample_networks"] = len(doc2.get("Networks", [])) == 23
    else:
        checks["profile_json_sample_present"] = False
    # 3. profile.enc se informa como pendiente.
    try:
        decode(b"AAAA", filename="profile.enc")
        checks["profile_enc_reported"] = False
    except DecodeError as exc:
        checks["profile_enc_reported"] = exc.code == "PROFILE_ENC_KEY"
    # 4. JSON plano (config.json generado por la app) pasa tal cual.
    plain = json.dumps({"Version": "46.1", "Servers": [], "Networks": []}).encode()
    doc3 = decode(plain, filename="config.json")
    checks["plain_json_passthrough"] = doc3.get("Version") == "46.1"
    return checks


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("file", nargs="?", type=Path,
                        help="profile.json (doble capa Tink+XXTEA) o JSON plano")
    parser.add_argument("--stdin", action="store_true", help="Leer desde stdin")
    parser.add_argument("-o", "--output", type=Path, help="Guardar JSON; por defecto stdout")
    parser.add_argument("--self-test", action="store_true",
                        help="Verifica profile.json con un archivo sintetico y la muestra real")
    args = parser.parse_args(argv)
    try:
        if args.self_test:
            result = _self_test()
            print(json.dumps(result, ensure_ascii=False, indent=2))
            return 0 if all(result.values()) else 1
        if args.stdin:
            raw = sys.stdin.buffer.read(MAX_BYTES + 1)
            name = "profile.json"
        elif args.file is not None:
            raw = _read(args.file)
            name = args.file.name
        else:
            parser.error("se requiere un archivo o --stdin (o --self-test)")
        doc = decode(raw, filename=name)
        rendered = json.dumps(doc, ensure_ascii=False, indent=2, allow_nan=False) + "\n"
        if args.output:
            args.output.write_text(rendered, encoding="utf-8")
        else:
            sys.stdout.write(rendered)
        return 0
    except DecodeError as exc:
        print(json.dumps({"error": exc.code, "message": str(exc)}, ensure_ascii=False),
              file=sys.stderr)
        return 1
    except OSError:
        print(json.dumps({"error": "IO_ERROR", "message": "No se pudo leer o escribir el archivo."}),
              file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())

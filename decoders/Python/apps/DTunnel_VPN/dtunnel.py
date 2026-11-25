#!/usr/bin/env python3
"""DTunnel VPN 4.5.8 (paquete com.dtunnel.ads, versionCode 21) — catálogo gRPC.

Método verificado EN VIVO 2026-11-25 contra grpc.dtunnel.com.br:443 con el
user_id descifrado del assets/user_id.txt de ESTE APK. La 4.5.8 ya NO usa el
sistema viejo de dtmod.cloud (DTunnel.py cubre ese sistema, 4.2.5): todo el
catálogo, la configuración de la app y los textos llegan por gRPC, con TLS,
sin contraseña de cuenta. El identificador es un token por build que viaja
en el propio APK y se descifra en el cliente (ver decrypt_user_id_token);
quien ejecuta el script lo aporta con --user-id-file (assets/user_id.txt)
o con --user-id (el UUID ya descifrado). Nunca se incrusta aquí.

Servicios gRPC (proto com.app.*), todos con request {user_id: string = 1}
y metadata client-version: 4.5.8:
    com.app.config.ConfigService/getVersion     -> {version: int64 = 2, ...}
    com.app.config.ConfigService/getConfigsV2   -> {data: string = 1}
    com.app.config.ConfigService/getCategories  -> {data: repeated Category = 1}
    com.app.config.ConfigService/getCdns        -> {data: repeated CDN = 1}
    com.app.appConfig.AppConfigService/getVersion -> {version: int64 = 1}
    com.app.appConfig.AppConfigService/getConfigs -> {data: string = 1}
    com.app.appText.TextService/getVersion      -> {version: int64 = 1}
    com.app.appText.TextService/getTexts        -> {data: repeated Text = 1}

Cifrado del catálogo (qc/a.java, aesGCMDecoder; el `data` de getConfigsV2):
    outer  = Base64(data)
    int32 BE N | N bytes Base64 -> material; key = SHA-256(material)
    resto Base64 -> blob: nonce blob[0:12], tag blob[12:28], ct blob[28:]
    texto  = AES-256-GCM(key, nonce, ct || tag) -> JSON UTF-8 (lista de perfiles)
    La clave viaja con la respuesta: no hay secreto que guardar.

Cifrado de app_config (nc/a.java, appConfigEncoder):
    outer  = Base64(data)
    int32 BE L1 | L1 bytes Base64 -> salt (16 B)
    int32 BE L2 | L2 bytes Base64 -> password (texto ASCII)
    16 B IV | resto cifrado
    key    = PBKDF2-HMAC-SHA1(password, salt, 64 iteraciones, 256 bits)
    texto  = AES-256-CBC-PKCS#7(key, IV) -> JSON UTF-8 (lista de ajustes)

Token user_id (mc/c.java, userIdDecrypter; assets/user_id.txt es
"<Base64(Base64(bytes))>:<sha256 hex>"):
    bytes  = Base64(Base64(token)); bytes[0] == 7 (versión)
    nonce  = bytes[1:13]; key = bytes[13:45]; ct+tag = bytes[45:]
    user_id = AES-256-GCM(key, nonce, ct) -> UUID en texto (36 caracteres)
    La clave AES viaja dentro del propio token.

assets/a.json (formato verificado contra el asset de ESTE APK):
    8 bytes de cabecera + cuerpo XOR con clave repetida de 8 bytes
    (constante de formato afafa7a78c8c2121) -> JSON UTF-8 con 8 pares
    {ak, av, ek, ev, dk, dv, csk, csv}, cada valor 32 caracteres hex.
    Su uso exacto en runtime no se trazó a un call-site (el lector no está
    en classes2.dex); se documenta el formato, no su función.

Los textos (TextService/getTexts) llegan en claro por protobuf, sin cifrar.
Las categorías son TIM / VIVO / CLARO; los CDN son front y gcloud.

Dependencias: grpcio y pycryptodome (Crypto). Sin red, el script solo
descifra datos guardados (--data-file) o enlaces vpn:// heredados.

Uso:
    python3 dtunnel.py --user-id-file user_id.txt --kind catalog
    python3 dtunnel.py --user-id-file user_id.txt --kind appconfig
    python3 dtunnel.py --user-id-file user_id.txt --kind texts
    python3 dtunnel.py --user-id-file user_id.txt --kind categories
    python3 dtunnel.py --user-id-file user_id.txt --kind cdns
    python3 dtunnel.py --user-id-file user_id.txt --kind version
    python3 dtunnel.py --data-file fixtures_catalog_data_v436.txt --kind catalog
    python3 dtunnel.py --data-file appconfig_data.txt --kind appconfig
    python3 dtunnel.py --link 'vpn://BASE64_DEL_JSON'   (formato heredado 4.2.5)
    python3 dtunnel.py --self-test
"""
from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import json
import math
import re
import struct
import sys
from pathlib import Path
from typing import Any

MAX_BYTES = 32 * 1024 * 1024
MAX_NODES = 1_000_000
MAX_DEPTH = 64
GRPC_HOST = "grpc.dtunnel.com.br:443"
CLIENT_VERSION = "4.5.8"
# Constante de formato del asset a.json (no es una credencial de cuenta).
A_JSON_XOR_KEY = bytes.fromhex("afafa7a78c8c2121")

METHODS = {
    "version": ("com.app.config.ConfigService", "getVersion"),
    "catalog": ("com.app.config.ConfigService", "getConfigsV2"),
    "categories": ("com.app.config.ConfigService", "getCategories"),
    "cdns": ("com.app.config.ConfigService", "getCdns"),
    "appversion": ("com.app.appConfig.AppConfigService", "getVersion"),
    "appconfig": ("com.app.appConfig.AppConfigService", "getConfigs"),
    "textsversion": ("com.app.appText.TextService", "getVersion"),
    "texts": ("com.app.appText.TextService", "getTexts"),
}
# Qué decodificador usa el campo `data` de cada respuesta.
DATA_DECODERS = {"catalog": "aesgcm", "appconfig": "pbkdf2cbc"}


class DecodeError(ValueError):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


# ------------------------------------------------------------- utilidades
def _text(data: bytes | str) -> str:
    if not isinstance(data, (bytes, str)):
        raise DecodeError("FORMAT_ERROR", "La entrada debe ser bytes o texto UTF-8.")
    if isinstance(data, bytes) and len(data) > MAX_BYTES:
        raise DecodeError("SIZE_LIMIT", "La entrada supera el límite de tamaño.")
    try:
        text = data.decode("utf-8-sig") if isinstance(data, bytes) else data.removeprefix("\ufeff")
        if len(text.encode("utf-8")) > MAX_BYTES:
            raise DecodeError("SIZE_LIMIT", "La entrada supera el límite de tamaño.")
    except UnicodeError as exc:
        raise DecodeError("FORMAT_ERROR", "La entrada no es UTF-8 válido.") from exc
    return text.strip()


def _b64decode_padded(text: str) -> bytes:
    compact = re.sub(r"[ \t\r\n]", "", text)
    return base64.b64decode(compact + "=" * (-len(compact) % 4), validate=False)


def _base64(text: str) -> bytes:
    compact = re.sub(r"[ \t\r\n]", "", text)
    if not re.fullmatch(r"[A-Za-z0-9+/]+={0,2}", compact) or len(compact) % 4 == 1:
        raise DecodeError("FORMAT_ERROR", "Se esperaba Base64 estándar.")
    try:
        return base64.b64decode(compact + "=" * (-len(compact) % 4), validate=True)
    except (ValueError, binascii.Error) as exc:
        raise DecodeError("FORMAT_ERROR", "Base64 inválido.") from exc


def _unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate key")
        result[key] = value
    return result


def _nonfinite(_value):
    raise ValueError("nonfinite number")


def _validate(doc: Any) -> Any:
    pending = [(doc, 0)]
    count = 0
    while pending:
        value, depth = pending.pop()
        count += 1
        if depth > MAX_DEPTH or count > MAX_NODES:
            raise DecodeError("SIZE_LIMIT", "El JSON supera el límite de complejidad.")
        if isinstance(value, dict):
            pending.extend((v, depth + 1) for v in value.values())
            pending.extend((k, depth + 1) for k in value)
        elif isinstance(value, list):
            pending.extend((v, depth + 1) for v in value)
        elif isinstance(value, float) and not math.isfinite(value):
            raise DecodeError("INVALID_JSON", "El JSON contiene un número no finito.")
        elif isinstance(value, str):
            try:
                value.encode("utf-8")
            except UnicodeError as exc:
                raise DecodeError("INVALID_JSON", "El JSON contiene Unicode inválido.") from exc
    return doc


def _json(text: str) -> Any:
    try:
        doc = json.loads(text, object_pairs_hook=_unique, parse_constant=_nonfinite)
    except (ValueError, RecursionError) as exc:
        raise DecodeError("INVALID_JSON", "JSON inválido o con claves duplicadas.") from exc
    return _validate(doc)


def _aes_gcm_decrypt(key: bytes, nonce: bytes, ciphertext_and_tag: bytes) -> bytes:
    try:
        from Crypto.Cipher import AES
    except ImportError as exc:
        raise DecodeError("MISSING_DEPENDENCY", "Falta pycryptodome (Crypto).") from exc
    if len(ciphertext_and_tag) < 16:
        raise DecodeError("DECRYPT_FAILED", "El cifrado GCM es demasiado corto para llevar tag.")
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    try:
        return cipher.decrypt_and_verify(ciphertext_and_tag[:-16], ciphertext_and_tag[-16:])
    except ValueError as exc:
        raise DecodeError("DECRYPT_FAILED", "No se pudo descifrar (tag GCM inválido).") from exc


# ------------------------------------------------------------- token user_id
def decrypt_user_id_token(token: str) -> str:
    """Doble Base64, versión 7, AES-256-GCM con clave dentro del token."""
    token = _text(token).split(":")[0]
    try:
        inner = _b64decode_padded(_b64decode_padded(token).decode("utf-8"))
    except (ValueError, binascii.Error, UnicodeError) as exc:
        raise DecodeError("FORMAT_ERROR", "El token user_id no es doble Base64 válido.") from exc
    if len(inner) < 45 or inner[0] != 7:
        raise DecodeError("FORMAT_ERROR", "El token user_id no tiene versión 7 o es demasiado corto.")
    plain = _aes_gcm_decrypt(inner[13:45], inner[1:13], inner[45:])
    try:
        user_id = plain.decode("utf-8")
    except UnicodeError as exc:
        raise DecodeError("DECRYPT_FAILED", "El user_id descifrado no es UTF-8 válido.") from exc
    if not re.fullmatch(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}", user_id):
        raise DecodeError("DECRYPT_FAILED", "El user_id descifrado no tiene forma de UUID.")
    return user_id


def load_user_id(user_id_file: Path | None, user_id: str | None) -> str:
    if user_id_file is not None:
        raw = _text(user_id_file.read_bytes())
        return decrypt_user_id_token(raw)
    if user_id is not None:
        user_id = _text(user_id)
        if not re.fullmatch(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}", user_id):
            raise DecodeError("CREDENTIALS_REQUIRED", "Se necesita un UUID válido o un user_id.txt.")
        return user_id
    raise DecodeError("CREDENTIALS_REQUIRED",
                      "Use --user-id-file user_id.txt (del APK) o --user-id <UUID descifrado>.")


# ------------------------------------------------------------- a.json
def decode_a_json(data: bytes | str) -> dict:
    """Cabecera de 8 bytes + cuerpo XOR con clave repetida de 8 bytes."""
    if isinstance(data, (bytes, str)):
        try:
            doc = json.loads(_text(data))
            raw = bytes(int(x) & 0xFF for x in doc["a"])
        except (ValueError, KeyError, TypeError):
            raw = data if isinstance(data, bytes) else _text(data).encode("utf-8")
    else:
        raise DecodeError("FORMAT_ERROR", "a.json debe ser bytes o texto.")
    if len(raw) < 9:
        raise DecodeError("TRUNCATED", "a.json es demasiado corto (cabecera de 8 bytes + cuerpo).")
    body = bytes(b ^ A_JSON_XOR_KEY[i % 8] for i, b in enumerate(raw[8:]))
    try:
        text = body.decode("utf-8")
    except UnicodeError as exc:
        raise DecodeError("DECRYPT_FAILED", "a.json no descifra a UTF-8 con este formato.") from exc
    doc = _json(text)
    if not isinstance(doc, dict):
        raise DecodeError("WRONG_DOCUMENT", "a.json debe descifrar a un objeto JSON.")
    return doc


# ------------------------------------------------------------- catálogo (AES-GCM)
def aesgcm_decode_text(data: bytes | str) -> str:
    """Sobre qc/a: int32 + material (key=SHA-256) + blob GCM (nonce|tag|ct)."""
    outer = _base64(_text(data))
    if len(outer) < 4:
        raise DecodeError("TRUNCATED", "La respuesta no trae la cabecera de longitud.")
    (n,) = struct.unpack(">I", outer[:4])
    if len(outer) < 4 + n:
        raise DecodeError("TRUNCATED", "La respuesta no trae el material de clave completo.")
    try:
        key_material = base64.b64decode(outer[4:4 + n])
    except (ValueError, binascii.Error) as exc:
        raise DecodeError("FORMAT_ERROR", "El material de clave no es Base64 válido.") from exc
    key = hashlib.sha256(key_material).digest()
    try:
        blob = base64.b64decode(outer[4 + n:])
    except (ValueError, binascii.Error) as exc:
        raise DecodeError("FORMAT_ERROR", "El cuerpo cifrado no es Base64 válido.") from exc
    if len(blob) < 28:
        raise DecodeError("TRUNCATED", "El cuerpo cifrado es demasiado corto (nonce 12 + tag 16).")
    plain = _aes_gcm_decrypt(key, blob[:12], blob[28:] + blob[12:28])
    try:
        return plain.decode("utf-8")
    except UnicodeError as exc:
        raise DecodeError("DECRYPT_FAILED", "El catálogo descifrado no es UTF-8 válido.") from exc


def decode_catalog(data: bytes | str) -> list[dict]:
    doc = _json(aesgcm_decode_text(data))
    if not isinstance(doc, list):
        raise DecodeError("WRONG_DOCUMENT", "El catálogo debe ser una lista JSON de perfiles.")
    for item in doc:
        if not isinstance(item, dict):
            raise DecodeError("WRONG_DOCUMENT", "Cada perfil del catálogo debe ser un objeto.")
    return _validate(doc)


# ------------------------------------------------------------- app_config (PBKDF2+CBC)
def appconfig_decode_text(data: bytes | str) -> str:
    """Sobre nc/a: salt + password (PBKDF2-HMAC-SHA1, 64 it., 256 bits) + IV + AES-CBC."""
    try:
        from Crypto.Cipher import AES
        from Crypto.Hash import SHA1
        from Crypto.Protocol.KDF import PBKDF2
    except ImportError as exc:
        raise DecodeError("MISSING_DEPENDENCY", "Falta pycryptodome (Crypto).") from exc
    outer = _base64(_text(data))
    if len(outer) < 8:
        raise DecodeError("TRUNCATED", "La respuesta no trae las cabeceras de longitud.")
    (l1,) = struct.unpack(">I", outer[:4])
    if len(outer) < 4 + l1 + 4:
        raise DecodeError("TRUNCATED", "La respuesta no trae la sal completa.")
    try:
        salt = base64.b64decode(outer[4:4 + l1])
        (l2,) = struct.unpack(">I", outer[4 + l1:8 + l1])
        password = base64.b64decode(outer[8 + l1:8 + l1 + l2]).decode("utf-8")
    except (ValueError, binascii.Error, UnicodeError) as exc:
        raise DecodeError("FORMAT_ERROR", "La sal o la contraseña no son Base64 válido.") from exc
    off = 8 + l1 + l2
    if len(outer) < off + 16:
        raise DecodeError("TRUNCATED", "La respuesta no trae el IV completo.")
    key = PBKDF2(password.encode("utf-8"), salt, dkLen=32, count=64, hmac_hash_module=SHA1)
    try:
        plain = AES.new(key, AES.MODE_CBC, iv=outer[off:off + 16]).decrypt(outer[off + 16:])
    except ValueError as exc:
        raise DecodeError("DECRYPT_FAILED", "No se pudo descifrar app_config.") from exc
    if not plain:
        raise DecodeError("DECRYPT_FAILED", "app_config descifrado está vacío.")
    pad = plain[-1]
    if pad < 1 or pad > 16 or plain[-pad:] != bytes([pad]) * pad:
        raise DecodeError("DECRYPT_FAILED", "Padding PKCS#7 inválido en app_config.")
    try:
        return plain[:-pad].decode("utf-8")
    except UnicodeError as exc:
        raise DecodeError("DECRYPT_FAILED", "app_config descifrado no es UTF-8 válido.") from exc


def decode_appconfig(data: bytes | str) -> list[dict]:
    doc = _json(appconfig_decode_text(data))
    if not isinstance(doc, list):
        raise DecodeError("WRONG_DOCUMENT", "app_config debe ser una lista JSON de ajustes.")
    for item in doc:
        if not isinstance(item, dict):
            raise DecodeError("WRONG_DOCUMENT", "Cada ajuste de app_config debe ser un objeto.")
    return _validate(doc)


# ------------------------------------------------------------- enlaces heredados (4.2.5)
def decode_vpn_link(data: bytes | str) -> dict:
    """vpn://Base64(JSON del perfil), sin cifrar. Formato de la 4.2.5; la 4.5.8
    ya no declara este esquema, pero los enlaces viejos siguen este formato."""
    text = _text(data)
    if not text.startswith("vpn://"):
        raise DecodeError("FORMAT_ERROR", "Se esperaba un enlace vpn://.")
    plain = _base64(text[6:]).decode("utf-8")
    doc = _json(plain)
    if not isinstance(doc, dict):
        raise DecodeError("WRONG_DOCUMENT", "El enlace debe contener un objeto JSON.")
    return doc


def redact_catalog(profiles: list[dict]) -> list[dict]:
    """Quita las credenciales de auth; conserva todo lo demás tal cual."""
    redacted = []
    for profile in profiles:
        item = json.loads(json.dumps(profile, ensure_ascii=False))
        item["auth"] = {"username": None, "password": None, "v2ray_uuid": None}
        redacted.append(item)
    return redacted


# ------------------------------------------------------------- protobuf mínimo
def _pb_varint(value: int) -> bytes:
    out = bytearray()
    while True:
        chunk = value & 0x7F
        value >>= 7
        if value:
            out.append(chunk | 0x80)
        else:
            out.append(chunk)
            return bytes(out)


def _pb_str(field: int, text: str) -> bytes:
    raw = text.encode("utf-8")
    return bytes([(field << 3) | 2]) + _pb_varint(len(raw)) + raw


def _pb_parse(buf: bytes) -> list:
    """Devuelve [(campo, valor)] con valor int o bytes; suficiente para estas respuestas."""
    out = []
    i = 0
    while i < len(buf):
        tag_start = i
        tag, i = _pb_read_varint(buf, i)
        field, wire = tag >> 3, tag & 7
        if wire == 2:
            length, i = _pb_read_varint(buf, i)
            if i + length > len(buf):
                raise DecodeError("INVALID_PROTOBUF", "Campo de longitud fuera del mensaje.")
            out.append((field, buf[i:i + length]))
            i += length
        elif wire == 0:
            value, i = _pb_read_varint(buf, i)
            out.append((field, value))
        elif wire == 5:
            out.append((field, buf[i:i + 4]))
            i += 4
        elif wire == 1:
            out.append((field, buf[i:i + 8]))
            i += 8
        else:
            raise DecodeError("INVALID_PROTOBUF", f"Tipo de cable {wire} no soportado (offset {tag_start}).")
    return out


def _pb_read_varint(buf: bytes, i: int) -> tuple[int, int]:
    value = 0
    shift = 0
    while True:
        if i >= len(buf):
            raise DecodeError("INVALID_PROTOBUF", "Varint truncado.")
        byte = buf[i]
        i += 1
        value |= (byte & 0x7F) << shift
        shift += 7
        if not byte & 0x80:
            return value, i
        if shift > 70:
            raise DecodeError("INVALID_PROTOBUF", "Varint demasiado largo.")


def _pb_text_field(message: bytes, field: int) -> str:
    for number, value in _pb_parse(message):
        if number == field and isinstance(value, bytes):
            return value.decode("utf-8")
    raise DecodeError("INVALID_PROTOBUF", f"La respuesta no trae el campo de texto {field}.")


def _pb_int_field(message: bytes, field: int) -> int:
    for number, value in _pb_parse(message):
        if number == field and isinstance(value, int):
            return value
    raise DecodeError("INVALID_PROTOBUF", f"La respuesta no trae el campo entero {field}.")


# ------------------------------------------------------------- gRPC en vivo
def grpc_call(method: str, request: bytes, timeout: float = 60.0) -> bytes:
    try:
        import grpc
    except ImportError as exc:
        raise DecodeError("MISSING_DEPENDENCY", "Falta grpcio para llamar al servidor gRPC.") from exc
    channel = grpc.secure_channel(
        GRPC_HOST, grpc.ssl_channel_credentials(),
        options=(("grpc.enable_http_proxy", 1),))
    stub = channel.unary_unary(method, request_serializer=lambda b: b,
                               response_deserializer=lambda b: b)
    try:
        return stub(request, metadata=(("client-version", CLIENT_VERSION),), timeout=timeout)
    except grpc.RpcError as exc:
        code = exc.code().name if hasattr(exc, "code") else "UNKNOWN"
        raise DecodeError("DOWNLOAD_FAILED", f"gRPC {method} falló: {code}: {exc.details()}") from exc
    finally:
        channel.close()


def fetch(kind: str, user_id: str) -> Any:
    """Llama al servicio en vivo y devuelve el documento descifrado/parseado."""
    if kind not in METHODS:
        raise DecodeError("FORMAT_ERROR", "Tipo de actualización desconocido.")
    service, method = METHODS[kind]
    response = grpc_call(f"/{service}/{method}", _pb_str(1, user_id))
    if kind in ("version", "appversion", "textsversion"):
        field = 2 if kind == "version" else 1
        return {"version": _pb_int_field(response, field)}
    if kind in DATA_DECODERS:
        data = _pb_text_field(response, 1)
        return decode_catalog(data) if DATA_DECODERS[kind] == "aesgcm" else decode_appconfig(data)
    if kind == "texts":
        texts = []
        for number, value in _pb_parse(response):
            if number == 1 and isinstance(value, bytes):
                item = dict(_pb_parse(value))
                label = item.get(1, b"").decode("utf-8") if isinstance(item.get(1), bytes) else ""
                text = item.get(2, b"").decode("utf-8") if isinstance(item.get(2), bytes) else ""
                texts.append({"label": label, "text": text})
        return texts
    if kind == "categories":
        categories = []
        for number, value in _pb_parse(response):
            if number == 1 and isinstance(value, bytes):
                item = dict(_pb_parse(value))
                categories.append({
                    "id": item.get(1),
                    "name": item.get(2, b"").decode("utf-8") if isinstance(item.get(2), bytes) else None,
                    "color": item.get(3, b"").decode("utf-8") if isinstance(item.get(3), bytes) else None,
                    "order": item.get(4),
                })
        return categories
    if kind == "cdns":
        cdns = []
        for number, value in _pb_parse(response):
            if number == 1 and isinstance(value, bytes):
                item = dict(_pb_parse(value))
                cdns.append({
                    "id": item.get(1, b"").decode("utf-8") if isinstance(item.get(1), bytes) else None,
                    "name": item.get(2, b"").decode("utf-8") if isinstance(item.get(2), bytes) else None,
                    "url": item.get(3, b"").decode("utf-8") if isinstance(item.get(3), bytes) else None,
                })
        return cdns
    raise DecodeError("FORMAT_ERROR", "Tipo de actualización desconocido.")


def decode_data_file(data: bytes | str, kind: str) -> Any:
    if kind == "catalog":
        return decode_catalog(data)
    if kind == "appconfig":
        return decode_appconfig(data)
    raise DecodeError("FORMAT_ERROR", "Solo catalog y appconfig se descifran desde un archivo guardado.")


# ------------------------------------------------------------- CLI
def _read(path: Path, limit: int) -> bytes:
    with path.open("rb") as stream:
        data = stream.read(limit + 1)
    if len(data) > limit:
        raise DecodeError("SIZE_LIMIT", "El archivo supera el límite de tamaño.")
    return data


def _summarize(result, kind: str) -> None:
    if kind == "catalog" and isinstance(result, list):
        from collections import Counter
        modes = Counter(i.get("mode") for i in result)
        payloads = sum(1 for i in result if (i.get("config_payload") or {}).get("payload"))
        print(f"Perfiles: {len(result)}", file=sys.stderr)
        print("Modos: " + ", ".join(f"{k}: {v}" for k, v in modes.most_common()), file=sys.stderr)
        print(f"Con payload: {payloads} de {len(result)}", file=sys.stderr)
    elif isinstance(result, list):
        print(f"Miembros: {len(result)}", file=sys.stderr)
    elif isinstance(result, dict) and "version" in result:
        print(f"Versión: {result['version']}", file=sys.stderr)


def _self_test() -> int:
    ok = 0

    def check(name, cond):
        nonlocal ok
        print(("OK   " if cond else "FAIL ") + name)
        if not cond:
            raise SystemExit(1)
        ok += 1

    from Crypto.Cipher import AES
    from Crypto.Hash import SHA1
    from Crypto.Protocol.KDF import PBKDF2
    from Crypto.Random import get_random_bytes

    # 1. Token user_id: cifrar un UUID de prueba con el formato v7 y descifrarlo.
    test_uuid = "11111111-2222-3333-4444-555555555555"
    key = get_random_bytes(32)
    nonce = get_random_bytes(12)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    ct, tag = cipher.encrypt_and_digest(test_uuid.encode())
    blob = b"\x07" + nonce + key + ct + tag
    token = base64.b64encode(base64.b64encode(blob)).decode()
    check("Token user_id round-trip", decrypt_user_id_token(token) == test_uuid)
    try:
        decrypt_user_id_token(base64.b64encode(base64.b64encode(b"\x08" + blob[1:])).decode())
        check("Token con versión distinta rechazado", False)
    except DecodeError:
        check("Token con versión distinta rechazado", True)

    # 2. Catálogo AES-GCM: construir un sobre y descifrarlo.
    profiles = [{"id": 1, "name": "prueba", "mode": "DTUNNEL",
                 "config_payload": {"payload": "GET / HTTP/1.1\r\nHost: ejemplo.test\r\n\r\n", "sni": ""}}]
    plain = json.dumps(profiles, ensure_ascii=False).encode()
    material = get_random_bytes(64)
    ckey = hashlib.sha256(material).digest()
    cnonce = get_random_bytes(12)
    ccipher = AES.new(ckey, AES.MODE_GCM, nonce=cnonce)
    cct, ctag = ccipher.encrypt_and_digest(plain)
    blob = cnonce + ctag + cct
    envelope = struct.pack(">I", len(base64.b64encode(material))) + base64.b64encode(material) + base64.b64encode(blob)
    data = base64.b64encode(envelope).decode()
    dec = decode_catalog(data)
    check("Catálogo AES-GCM round-trip", dec[0]["name"] == "prueba" and "ejemplo.test" in dec[0]["config_payload"]["payload"])
    check("Catálogo redactado quita auth", redact_catalog([{"auth": {"username": "x", "password": "y", "v2ray_uuid": "z"}}])[0]["auth"] == {"username": None, "password": None, "v2ray_uuid": None})

    # 3. app_config PBKDF2+CBC: construir un sobre y descifrarlo.
    settings = [{"name": "APP_ADS_ENABLED", "type": "BOOLEAN", "value": True}]
    s_plain = json.dumps(settings, ensure_ascii=False).encode()
    pad = 16 - (len(s_plain) % 16)
    s_plain_padded = s_plain + bytes([pad]) * pad
    salt = get_random_bytes(16)
    password = "0123456789abcdef0123456789abcdef"
    skey = PBKDF2(password.encode(), salt, dkLen=32, count=64, hmac_hash_module=SHA1)
    iv = get_random_bytes(16)
    sct = AES.new(skey, AES.MODE_CBC, iv=iv).encrypt(s_plain_padded)
    senvelope = (struct.pack(">I", len(base64.b64encode(salt))) + base64.b64encode(salt)
                 + struct.pack(">I", len(base64.b64encode(password.encode()))) + base64.b64encode(password.encode())
                 + iv + sct)
    sdata = base64.b64encode(senvelope).decode()
    check("app_config PBKDF2+CBC round-trip", decode_appconfig(sdata) == settings)

    # 4. a.json: construir un asset sintético y descifrarlo.
    a_doc = {"ak": "0" * 32, "av": "1" * 32}
    a_body = json.dumps(a_doc, separators=(",", ":")).encode()
    a_raw = b"\x00" * 8 + bytes(b ^ A_JSON_XOR_KEY[i % 8] for i, b in enumerate(a_body))
    a_asset = json.dumps({"a": [b if b < 128 else b - 256 for b in a_raw]})
    check("a.json XOR round-trip", decode_a_json(a_asset) == a_doc)

    # 5. Protobuf mínimo: request user_id y respuesta de versión.
    req = _pb_str(1, test_uuid)
    check("Protobuf request user_id", req == b"\n$" + test_uuid.encode())
    check("Protobuf parse versión", _pb_int_field(b"\x10\xb4\x03", 2) == 436)

    # 6. Enlace vpn:// heredado.
    profile = {"id": 7, "name": "perfil prueba", "mode": "SSL_DIRECT"}
    link = "vpn://" + base64.b64encode(json.dumps(profile, ensure_ascii=False).encode()).decode()
    check("Enlace vpn:// heredado round-trip", decode_vpn_link(link) == profile)
    try:
        decode_vpn_link("https://ejemplo.test/x")
        check("Enlace sin vpn:// rechazado", False)
    except DecodeError:
        check("Enlace sin vpn:// rechazado", True)

    # 7. Fixture vivo: el `data` real de getConfigsV2 (v436) descifra a 16 perfiles.
    fixture = Path(__file__).resolve().parent / "fixtures_catalog_data_v436.txt"
    if fixture.exists():
        live = decode_catalog(fixture.read_bytes())
        check("Fixture vivo v436 (16 perfiles DTUNNEL)",
              len(live) == 16 and all(p.get("mode") == "DTUNNEL" for p in live)
              and live[0]["name"] == "CLARO ➜ SSL")
    else:
        print("SKIP fixture vivo (falta fixtures_catalog_data_v436.txt)")
    print(f"SELF-TEST: TODO OK ({ok} pruebas)")
    return 0


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--user-id-file", type=Path, help="assets/user_id.txt del APK (token cifrado)")
    source.add_argument("--user-id", help="UUID ya descifrado")
    source.add_argument("--data-file", type=Path, help="Cadena `data` guardada (catalog o appconfig)")
    source.add_argument("--link", help="Enlace vpn:// heredado (4.2.5)")
    source.add_argument("--a-json", type=Path, help="Archivo assets/a.json del APK")
    source.add_argument("--self-test", action="store_true", help="Pruebas locales sin red (salvo fixture)")
    parser.add_argument("--kind", choices=sorted(set(METHODS) | {"catalog", "appconfig"}),
                        default="catalog", help="Qué pedir o descifrar")
    parser.add_argument("--redact", action="store_true", help="Quitar auth del catálogo en la salida")
    parser.add_argument("-o", "--output", type=Path, help="Guardar JSON completo; por defecto stdout")
    args = parser.parse_args(argv)
    if args.self_test:
        return _self_test()
    try:
        if args.a_json is not None:
            result = decode_a_json(_read(args.a_json, MAX_BYTES))
        elif args.link is not None:
            result = decode_vpn_link(args.link)
        elif args.data_file is not None:
            result = decode_data_file(_read(args.data_file, MAX_BYTES), args.kind)
        else:
            user_id = load_user_id(args.user_id_file, args.user_id)
            result = fetch(args.kind, user_id)
        if args.redact and isinstance(result, list) and args.kind == "catalog":
            result = redact_catalog(result)
        rendered = json.dumps(result, ensure_ascii=False, indent=2, allow_nan=False) + "\n"
        if args.output:
            args.output.write_text(rendered, encoding="utf-8")
        else:
            sys.stdout.write(rendered)
        _summarize(result, args.kind)
        return 0
    except DecodeError as exc:
        print(json.dumps({"error": exc.code, "message": str(exc)}, ensure_ascii=False), file=sys.stderr)
        return 1
    except UnicodeError:
        print(json.dumps({"error": "FORMAT_ERROR", "message": "El identificador no es UTF-8 válido."}), file=sys.stderr)
        return 1
    except OSError:
        print(json.dumps({"error": "IO_ERROR", "message": "No se pudo leer o escribir el archivo."}), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())

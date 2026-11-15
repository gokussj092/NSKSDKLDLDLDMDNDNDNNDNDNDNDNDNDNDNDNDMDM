#!/usr/bin/env python3
"""LinkLayer VPN - decodificador de archivos de configuracion .lnk (VER6).

App: LinkLayer VPN, com.newtoolsworks.linklayer, version 3.11.2 (versionCode 93),
minSdk 21. Version de Google Play (actualizada 31 ago 2026).

Formato: archivo .lnk que empieza por "VER6" (la app lo importa con
ACTION_VIEW, mimeType application/octet-stream, pathPattern .*\\.lnk).
Decodificador verificado en el repo SP-DECODE contra un exportado real
autorizado de LinkLayer 3.11.2 (93); las constantes (IV, XOR_SALT) se
verificaron en ESTE APK (libgojni.so: IV en 0x24f2260, XOR_SALT en 0x4691bc).

Capas VER6 (configuration.d en libgojni.so):
    VER6 | Blowfish-CFB64 (clave = ultimos 8 B) | AES-CFB128 |
    Salsa20 | CAST5-CFB64 | PBKDF2-SHA1 (32 iters, 1500 B XOR) |
    AES-CFB128 -> Go gob NativeConfig (25 campos raiz, 60 hojas)

El formato NO tiene MAC: los chequeos de esquema no son integridad
criptografica. Solo se acepta el esquema NativeConfig de 3.11.2.

Requiere PyCryptodome (python3 -m pip install pycryptodome). El script del
catalogo (LinkLayer.py) es solo stdlib; este decodificador de archivos no,
porque Blowfish/CAST5/Salsa20 no estan en la stdlib.

Uso:
    python3 LinkLayer_archivos.py perfil.lnk
    python3 LinkLayer_archivos.py perfil.lnk -o perfil.json
    python3 LinkLayer_archivos.py --stdin < perfil.lnk
    python3 LinkLayer_archivos.py --self-test   # round-trip sintetico
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

MAX_INPUT_SIZE = 8 * 1024 * 1024
MAX_STRING_SIZE = 1024 * 1024
IV = bytes.fromhex("a7734f9c12ac1b01a415f2c1fc78e66b")
XOR_SALT = b"sH3CIVoF#rWLtJo6"


class DecodeError(ValueError):
    """A configuration could not be decoded; messages contain no input values."""


class UnsupportedFormatError(DecodeError):
    pass


class UnsupportedVersionError(DecodeError):
    pass


class TruncatedFileError(DecodeError):
    pass


class InvalidConfigurationError(DecodeError):
    pass


class UnsupportedSchemaError(DecodeError):
    pass


class DependencyError(DecodeError):
    pass


# Primitive Go gob ids: bool=1, int=2, string=6. Nested struct ids vary.
SCHEMA = {
    "BlockAll": 1, "BlockPayloadSNI": 1, "BlockAuth": 1, "BlockServer": 1,
    "StartWithHWID": 1, "BlockRoot": 1, "BlockSniffer": 1, "OnlyCarrier": 6,
    "ExpireTimeConfig": 2, "MessageConfig": 6, "DeviceHWID": 6,
    "Username": 6, "Password": 6, "TypeAccount": 2, "TypeLayer": 2,
    "SSL": {"Single": 1, "Sni": 6, "Host": 6},
    "HTTP": {"Single": 1, "Payload": 6, "Host": 6},
    "HTTPSSL": {"Single": 1, "Host": 6, "SNI": 6, "Payload": 6},
    "WS": {"EnableHTTP": 1, "EnableTrue": 1, "SNI": 6, "Domain": 6, "Host": 6},
    "DNSTT": {"Domain": 6, "Pubkey": 6, "Timeout": 6, "Udp": 6},
    "UDPHysteria": {"Server": 6, "UdpPortRange": 6, "Obfs": 6,
                    "Up_mbps": 2, "Down_mbps": 2, "Insecure": 1,
                    "EnableInterval": 1, "Interval": 2},
    "HTTPDual": {"Host": 6, "Domain": 6, "SplitRequest": 1, "SNI": 6,
                 "EnableSSLTLS": 1, "Nchunks": 2, "Nparalels": 2, "Version": 6},
    "SSH": {"SSHLayer": 2, "SSHServer": 6, "SSHPayload": 6, "SSHProxy": 6,
            "SSHSni": 6, "SSHDNSPkey": 6, "SSHDomain": 6, "SSHDNSServer": 6},
    "IndexHTTPort": 2, "IndexSSLPort": 2,
}


class _Reader:
    def __init__(self, data: bytes):
        self.data = data
        self.pos = 0

    def take(self, size: int) -> bytes:
        if size < 0 or size > len(self.data) - self.pos:
            raise TruncatedFileError("Truncated Go gob data.")
        result = self.data[self.pos:self.pos + size]
        self.pos += size
        return result

    def uint(self) -> int:
        first = self.take(1)[0]
        if first < 128:
            return first
        size = 256 - first
        if size > 8:
            raise InvalidConfigurationError("Invalid Go gob integer width.")
        return int.from_bytes(self.take(size), "big")

    def sint(self) -> int:
        number = self.uint()
        return ~(number >> 1) if number & 1 else number >> 1

    def string(self) -> str:
        size = self.uint()
        if size > MAX_STRING_SIZE:
            raise InvalidConfigurationError("Go gob string exceeds size limit.")
        try:
            return self.take(size).decode("utf-8")
        except UnicodeDecodeError as exc:
            raise InvalidConfigurationError("Invalid UTF-8 configuration string.") from exc

    def expect(self, expected: int) -> None:
        if self.uint() != expected:
            raise InvalidConfigurationError("Invalid Go gob type definition.")

    def finish(self) -> None:
        if self.pos != len(self.data):
            raise InvalidConfigurationError("Trailing Go gob message data.")


def _read_type(reader: _Reader, type_id: int) -> tuple[str, list[tuple[str, int]]]:
    # wireType.StructT -> structType.CommonType -> Name, Id -> Field slice.
    if reader.uint() != 3:
        raise UnsupportedSchemaError("Only NativeConfig struct types are supported.")
    reader.expect(1)
    reader.expect(1)
    name = reader.string()
    reader.expect(1)
    if reader.sint() != type_id:
        raise InvalidConfigurationError("Go gob type id mismatch.")
    reader.expect(0)
    reader.expect(1)
    count = reader.uint()
    if not 1 <= count <= 64:
        raise InvalidConfigurationError("Invalid Go gob field count.")
    fields = []
    for _ in range(count):
        reader.expect(1)
        field_name = reader.string()
        reader.expect(1)
        field_type = reader.sint()
        reader.expect(0)
        fields.append((field_name, field_type))
    reader.expect(0)
    reader.expect(0)
    if len({field for field, _ in fields}) != count:
        raise InvalidConfigurationError("Duplicate Go gob field names.")
    return name, fields


def _validate_schema(types: dict, root_id: int) -> None:
    seen = set()

    def visit(type_id, expected, depth):
        if depth > 8 or type_id in seen or type_id not in types:
            raise UnsupportedSchemaError("Invalid NativeConfig type graph.")
        seen.add(type_id)
        _, fields = types[type_id]
        if [name for name, _ in fields] != list(expected):
            raise UnsupportedSchemaError("Unsupported NativeConfig fields.")
        for name, field_id in fields:
            wanted = expected[name]
            if isinstance(wanted, dict):
                visit(field_id, wanted, depth + 1)
            elif field_id != wanted:
                raise UnsupportedSchemaError("Unsupported NativeConfig field type.")

    if root_id not in types or types[root_id][0] != "NativeConfig":
        raise UnsupportedSchemaError("NativeConfig root type was not found.")
    visit(root_id, SCHEMA, 0)
    if seen != set(types):
        raise UnsupportedSchemaError("Unexpected Go gob type definitions.")


def _read_value(reader: _Reader, types: dict, type_id: int):
    if type_id == 1:
        value = reader.uint()
        if value not in (0, 1):
            raise InvalidConfigurationError("Invalid Go gob boolean.")
        return bool(value)
    if type_id == 2:
        return reader.sint()
    if type_id == 6:
        return reader.string()
    _, fields = types[type_id]

    def zero(field_id):
        if field_id == 1:
            return False
        if field_id == 2:
            return 0
        if field_id == 6:
            return ""
        return {name: zero(tid) for name, tid in types[field_id][1]}

    result = zero(type_id)
    index = -1
    while (delta := reader.uint()):
        index += delta
        if index >= len(fields):
            raise InvalidConfigurationError("Invalid Go gob field index.")
        name, field_id = fields[index]
        result[name] = _read_value(reader, types, field_id)
    return result


def decode_gob(data: bytes) -> dict:
    """Decode only the bounded NativeConfig schema verified in LinkLayer 3.11.2."""
    if len(data) > MAX_INPUT_SIZE:
        raise InvalidConfigurationError("Go gob data exceeds size limit.")
    stream = _Reader(data)
    types = {}
    result = None
    while stream.pos < len(data):
        message = _Reader(stream.take(stream.uint()))
        type_id = message.sint()
        if result is not None:
            raise InvalidConfigurationError("Unexpected additional Go gob message.")
        if type_id < 0:
            if -type_id < 65 or -type_id in types or len(types) >= 16:
                raise InvalidConfigurationError("Invalid Go gob type id or count.")
            types[-type_id] = _read_type(message, -type_id)
        else:
            _validate_schema(types, type_id)
            result = _read_value(message, types, type_id)
        message.finish()
    if result is None:
        raise InvalidConfigurationError("No NativeConfig value in Go gob data.")
    return result


def decrypt_gob(data: bytes) -> bytes:
    """Reproduce configuration.d in libgojni.so; return its Go gob payload."""
    if len(data) > MAX_INPUT_SIZE:
        raise InvalidConfigurationError("Configuration exceeds 8 MiB size limit.")
    if len(data) < 4:
        raise TruncatedFileError("Configuration header is truncated.")
    if data[:4] != b"VER6":
        if data[:3] == b"VER":
            raise UnsupportedVersionError("Only LinkLayer VER6 is supported.")
        raise UnsupportedFormatError("Expected a LinkLayer VER6 configuration.")
    if len(data) < 355:
        raise TruncatedFileError("VER6 container is truncated.")
    try:
        from Crypto.Cipher import AES, Blowfish, CAST, Salsa20
    except ImportError as exc:
        raise DependencyError("Install dependency: python -m pip install pycryptodome") from exc

    def cfb(cipher, key, content):
        size = cipher.block_size
        return cipher.new(key, cipher.MODE_CFB, iv=IV[:size],
                          segment_size=size * 8).decrypt(content)

    # VER6 | Blowfish-CFB(data | 72-byte AES-key material) | 8-byte Blowfish key.
    outer = cfb(Blowfish, data[-8:], data[4:-8])
    material = outer[-72:]
    aes_key = material[:16] + material[-16:][::-1]
    salsa_container = cfb(AES, aes_key, outer[:-72])
    if len(salsa_container) < 76:
        raise TruncatedFileError("Salsa20 container is truncated.")
    # The appended reversed 32-byte trailer is not used by NewSalsa20BlockCrypt.
    reversed_packet = salsa_container[32:-32][::-1]
    packet = reversed_packet[:8] + Salsa20.new(
        key=salsa_container[:32], nonce=reversed_packet[:8]
    ).decrypt(reversed_packet[8:])
    length = int.from_bytes(packet[8:12], "big")
    blocks = packet[12:]
    if length < 75 or len(blocks) != length * 3:
        raise InvalidConfigurationError("Invalid CAST5 segment length.")
    middle = blocks[length:2 * length]
    inner = cfb(CAST, middle[-16:], middle[:-16])
    flag, inner = inner[0], inner[1:]
    if flag == 1:
        split = len(inner) // 2
        inner = inner[split:][::-1] + inner[:split]
    elif flag != 0:
        raise InvalidConfigurationError("Invalid CAST5 ordering flag.")
    # The application XORs at most 1500 bytes, not a repeated 32-byte key.
    mask = hashlib.pbkdf2_hmac("sha1", inner[:16], XOR_SALT, 32, 1500)
    wrapped = bytearray(inner[16:])
    for index in range(min(len(wrapped), len(mask))):
        wrapped[index] ^= mask[index]
    key = bytearray(wrapped[-32:])
    key[0], key[-1] = key[-1], key[0]
    encrypted = bytes(wrapped[-42:-32]) + bytes(wrapped[:-42][::-1])
    return cfb(AES, bytes(key), encrypted)


def decode(data: bytes) -> dict:
    """Return all 60 NativeConfig leaf fields, including omitted Go zero values."""
    if len(data) > MAX_INPUT_SIZE + 1:
        raise InvalidConfigurationError("Configuration exceeds 8 MiB size limit.")
    return decode_gob(decrypt_gob(data))


def run(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path, nargs="?",
                        help="LinkLayer VER6 .lnk file")
    parser.add_argument("--stdin", action="store_true",
                        help="lee el .lnk desde stdin")
    parser.add_argument("--self-test", action="store_true",
                        help="pruebas: round-trip sintetico VER6")
    parser.add_argument("-o", "--output", type=Path, default=None,
                        help="guarda el JSON descifrado")
    parser.add_argument("--summary", action="store_true",
                        help="imprime solo un resumen de campos no vacios")
    args = parser.parse_args(argv)

    if args.self_test:
        return self_test()

    try:
        if args.stdin:
            data = sys.stdin.buffer.read(MAX_INPUT_SIZE + 1)
        elif args.input is not None:
            data = args.input.read_bytes()[:MAX_INPUT_SIZE + 1]
        else:
            parser.error("falta el archivo .lnk (o usa --stdin / --self-test)")
        result = decode(data)
    except (DecodeError, OSError) as exc:
        print(f"LinkLayer_archivos: {exc}", file=sys.stderr)
        return 2

    if args.output is not None:
        args.output.write_text(json.dumps(result, ensure_ascii=False, indent=2),
                               encoding="utf-8")
        print(f"guardado en {args.output}")
    if args.summary:
        print(_summary(result))
    else:
        print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


def _summary(result: dict) -> str:
    lines = ["LinkLayer VER6 - campos no vacios:"]
    for key, value in result.items():
        if isinstance(value, dict):
            filled = {k: v for k, v in value.items() if v not in ("", False, 0)}
            if filled:
                lines.append(f"  {key}: " + ", ".join(f"{k}={v!r}" for k, v in filled.items()))
        elif value not in ("", False, 0):
            lines.append(f"  {key}={value!r}")
    return "\n".join(lines)


# ------------------------------------------------------------------ self-test
# Codificador sintetico VER6 (inverso de decrypt_gob), solo para --self-test.
# Adaptado de la suite de pruebas del repo SP-DECODE (tests/test_linklayer_ver6.py).

def _uint(number):
    if number < 128:
        return bytes([number])
    data = number.to_bytes((number.bit_length() + 7) // 8, "big")
    return bytes([256 - len(data)]) + data


def _int(number):
    return _uint((~number << 1) | 1 if number < 0 else number << 1)


def _string(text):
    data = text.encode("utf-8")
    return _uint(len(data)) + data


def _zero(schema):
    return {name: _zero(kind) if isinstance(kind, dict)
            else False if kind == 1 else 0 if kind == 2 else ""
            for name, kind in schema.items()}


def _gob(value):
    types = []

    def register(name, schema):
        type_id = 65 + len(types)
        record = [type_id, name, []]
        types.append(record)
        for field, kind in schema.items():
            record[2].append((field, register(field, kind) if isinstance(kind, dict) else kind))
        return type_id

    root_id = register("NativeConfig", SCHEMA)
    messages = []
    for type_id, name, fields in types:
        common = b"\x01" + _string(name) + b"\x01" + _int(type_id) + b"\x00"
        field_data = b"".join(b"\x01" + _string(n) + b"\x01" + _int(t) + b"\x00"
                              for n, t in fields)
        message = (_int(-type_id) + b"\x03\x01" + common + b"\x01"
                   + _uint(len(fields)) + field_data + b"\x00\x00")
        messages.append(_uint(len(message)) + message)

    def encode(type_id, item):
        if type_id == 1:
            return _uint(int(item))
        if type_id == 2:
            return _int(item)
        if type_id == 6:
            return _string(item)
        fields = types[type_id - 65][2]
        output = b""
        previous = -1
        for index, (name, kind) in enumerate(fields):
            field = item[name]
            if field == "" or field is False or field == 0:
                continue
            output += _uint(index - previous) + encode(kind, field)
            previous = index
        return output + b"\x00"

    message = _int(root_id) + encode(root_id, value)
    return b"".join(messages) + _uint(len(message)) + message


def _noise(label, length):
    return hashlib.shake_256(label.encode()).digest(length)


def _export(gob, flag=0):
    from Crypto.Cipher import AES, Blowfish, CAST, Salsa20

    def encrypt(cipher, key, data):
        size = cipher.block_size
        return cipher.new(key, cipher.MODE_CFB, iv=IV[:size],
                          segment_size=size * 8).encrypt(data)

    key = _noise("inner aes", 32)
    encrypted = encrypt(AES, key, gob)
    swapped = key[-1:] + key[1:-1] + key[:1]
    wrapped = bytearray(encrypted[10:][::-1] + encrypted[:10] + swapped)
    password = _noise("inner pass", 16)
    mask = hashlib.pbkdf2_hmac("sha1", password, XOR_SALT, 32, 1500)
    for i in range(min(len(wrapped), len(mask))):
        wrapped[i] ^= mask[i]
    inner = password + wrapped
    if flag == 1:
        upper = len(inner) - len(inner) // 2
        inner = inner[upper:] + inner[:upper][::-1]
    cast_key = _noise("cast", 16)
    cast_block = encrypt(CAST, cast_key, bytes([flag]) + inner) + cast_key
    length = len(cast_block)
    nonce = _noise("nonce", 8)
    packet = (nonce + length.to_bytes(4, "big") + _noise("first padding", length)
              + cast_block + _noise("last padding", length))
    salsa_key = _noise("salsa", 32)
    packet = nonce + Salsa20.new(key=salsa_key, nonce=nonce).encrypt(packet[8:])
    salsa = salsa_key + packet[::-1] + _noise("salsa trailer", 32)
    outer_key = _noise("outer aes", 32)
    outer = (encrypt(AES, outer_key, salsa) + outer_key[:16]
             + _noise("outer padding", 40) + outer_key[16:][::-1])
    blowfish_key = _noise("blowfish", 8)
    return b"VER6" + encrypt(Blowfish, blowfish_key, outer) + blowfish_key


def self_test() -> int:
    checks = []
    expected = _zero(SCHEMA)
    expected.update(Username="usuario-prueba", Password="<redacted>",
                    MessageConfig="Prueba\nSegunda linea",
                    BlockAll=True, ExpireTimeConfig=-1, TypeAccount=1)
    expected["SSH"].update(SSHServer="example.invalid:22",
                           SSHPayload="GET / HTTP/1.1\r\nHost: example.invalid\r\n\r\n")
    gob = _gob(expected)
    fixture = _export(gob)
    checks.append(("round-trip VER6 (flag 0)", decode(fixture) == expected))
    checks.append(("decrypt_gob devuelve el gob", decrypt_gob(fixture) == gob))
    for flag in (0, 1):
        for length in (0, 1, 7, 8, 15, 16, 31, 32, 1500):
            exp2 = _zero(SCHEMA)
            exp2["MessageConfig"] = "x" * length
            checks.append((f"flag {flag} / MessageConfig len {length}",
                           decode(_export(_gob(exp2), flag)) == exp2))
    for prefix in (b"VER5", b"VER7", b"OTHER"):
        try:
            decode(prefix + fixture[4:])
            checks.append((f"rechaza cabecera {prefix!r}", False))
        except DecodeError:
            checks.append((f"rechaza cabecera {prefix!r}", True))
    for size in (0, 4, 100, 354, len(fixture) // 2, len(fixture) - 1):
        try:
            decode(fixture[:size])
            checks.append((f"rechaza truncado {size} B", False))
        except DecodeError:
            checks.append((f"rechaza truncado {size} B", True))

    ok = True
    for name, passed in checks:
        print(f"[{'OK' if passed else 'FAIL'}] {name}")
        ok = ok and passed
    print(f"self-test: {sum(1 for _, p in checks if p)}/{len(checks)} OK")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(run())

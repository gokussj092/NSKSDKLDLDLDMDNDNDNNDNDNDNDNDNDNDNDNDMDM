import json
import base64
import re
import contextlib
from typing import Optional, Dict, Any, Union, List
from Crypto.Cipher import AES

try:
    import msgpack
    MSGPACK_AVAILABLE = True
except ImportError:
    MSGPACK_AVAILABLE = False


def _format_top_level_json(data):
    """Formatea solo las claves del JSON raíz.

    Los valores que ya son objetos/listas JSON se conservan como un único valor
    JSON serializado, sin recorrer ni reordenar sus claves internas. Las cadenas
    que contienen JSON se dejan intactas para poder copiarlas y pegarlas tal cual.
    """
    if not isinstance(data, dict):
        if isinstance(data, (list, tuple)):
            value = json.dumps(data, ensure_ascii=False, separators=(",", ":"), default=str)
        elif data is None:
            value = "null"
        elif isinstance(data, bool):
            value = "true" if data else "false"
        else:
            value = str(data)
        return f"│[۞] DATA: {value}"

    lines = []
    for key, value in data.items():
        if isinstance(value, (dict, list, tuple)):
            rendered = json.dumps(
                value,
                ensure_ascii=False,
                separators=(",", ":"),
                default=str,
            )
        elif value is None:
            rendered = "null"
        elif isinstance(value, bool):
            rendered = "true" if value else "false"
        else:
            # Importante: una cadena que contiene otro JSON NO se vuelve a parsear.
            rendered = str(value)

        lines.append(f"│[۞] {key}: {rendered}")

    return "\n".join(lines)


class DTConstants:
    """Cryptographic artifacts and static keys for Dark Tunnel."""
    KEY_256: bytes = b"$B&E)H@McQfThWmZq4t7w!z%C*F-JaNd"
    KEY_192: bytes = b"F)J@NcRfUjXn2r4u7x!A%D*G"
    IV: bytes = bytes.fromhex("232e39185523184a5723586242200e05")


class DTDecryptor:
    """Core decryption and parsing engine for Dark Tunnel configs."""

    # Marker that opens the "encryptedLockedConfig" value inside the JSON
    # header of a darktunnel:// outer envelope.
    _ELC_MARKER: bytes = b'"encryptedLockedConfig":"'
    _B64_CHARS = frozenset(
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=_-"
    )

    @staticmethod
    def _base64_decode_safe(data: str) -> bytes:
        clean_data = data.replace("-", "+").replace("_", "/")
        if pad := len(clean_data) % 4:
            clean_data += "=" * (4 - pad)
        return base64.b64decode(clean_data)

    @staticmethod
    def _unpack_first(data: bytes) -> Any:
        """Unpack the first MessagePack object, ignoring trailing bytes.

        Some envelopes carry opaque bytes after the first object (the VLESS
        split-blob variant appends 272 trailing bytes after the outer map);
        unpackb would raise "extra data" on them. The app reads the first
        object and ignores the rest, so we do the same.
        """
        unpacker = msgpack.Unpacker(raw=False, strict_map_key=False)
        unpacker.feed(data)
        return next(unpacker)

    @classmethod
    def _split_blob_outer(cls, decoded: bytes) -> tuple:
        """Parse a split-blob outer envelope (VLESS variant).

        The outer payload is NOT valid JSON: it is a JSON header
        ({"type":"VLESS","name":...,"vlessTunnelConfig":{...},
        "encryptedLockedConfig":"<base64 part>") followed by the rest of the
        encrypted blob as raw bytes. Returns (header_dict, blob_bytes) or
        (None, None) when the shape does not match.
        """
        pos = decoded.find(cls._ELC_MARKER)
        if pos < 0:
            return None, None
        try:
            header = json.loads(decoded[: pos + len(cls._ELC_MARKER)] + b'"}')
        except Exception:
            return None, None
        b64_start = pos + len(cls._ELC_MARKER)
        end = b64_start
        while end < len(decoded) and decoded[end] in cls._B64_CHARS:
            end += 1
        if end == b64_start or end >= len(decoded):
            return None, None
        try:
            blob = cls._base64_decode_safe(
                decoded[b64_start:end].decode("ascii")
            ) + decoded[end:]
        except Exception:
            return None, None
        if not blob:
            return None, None
        return header, blob

    @staticmethod
    def _aes_cfb_decrypt(data: bytes, key: bytes, iv: bytes) -> bytes:
        return AES.new(key, AES.MODE_CFB, iv=iv, segment_size=128).decrypt(data)

    @staticmethod
    def _is_utf8_printable(value: bytes) -> bool:
        if not value: 
            return False
        try:
            return bool(re.fullmatch(r"[^\x00-\x08\x0B\x0C\x0E-\x1F\x7F]*", value.decode("utf-8")))
        except UnicodeDecodeError:
            return False

    @classmethod
    def _try_parse_json_string(cls, value: str) -> Union[Dict, List, str]:
        stripped = value.strip()
        if (stripped.startswith("{") and stripped.endswith("}")) or (stripped.startswith("[") and stripped.endswith("]")):
            with contextlib.suppress(Exception):
                fixed_json = re.sub(r'(:\s*)(\$[A-Za-z0-9_]+)', r'\1"\2"', stripped)
                return cls._normalize_for_json(json.loads(fixed_json))
        return value

    @classmethod
    def _normalize_for_json(cls, value: Any) -> Any:
        if isinstance(value, dict):
            return {k: cls._normalize_for_json(v) for k, v in value.items() if k != "Password"}

        if isinstance(value, list):
            return [cls._normalize_for_json(v) for v in value]

        if isinstance(value, bytes):
            return value.decode("utf-8") if cls._is_utf8_printable(value) else list(value)

        if isinstance(value, str):
            # No convertir JSON embebido en estructuras: debe permanecer copiable tal cual.
            return value

        return value

    @classmethod
    def _clean_encrypted(cls, value: Any, key: bytes, iv: bytes) -> Any:
        if isinstance(value, dict):
            cleaned = {}
            for k, v in value.items():
                if isinstance(k, str) and k.startswith("Encrypted") and v and isinstance(v, (bytes, bytearray)):
                    try:
                        cleaned[k] = cls._aes_cfb_decrypt(bytes(v), key, iv)
                    except Exception:
                        cleaned[k] = v
                else:
                    cleaned[k] = cls._clean_encrypted(v, key, iv)
            return cleaned

        if isinstance(value, list):
            return [cls._clean_encrypted(v, key, iv) for v in value]

        return value

    @classmethod
    def execute(cls, file_bytes: bytes) -> Optional[str]:
        if not MSGPACK_AVAILABLE:
            return None

        with contextlib.suppress(Exception):
            raw_input = file_bytes.decode('utf-8', errors='ignore').strip()
            if not raw_input: 
                return None
            
            if "://" in raw_input:
                raw_input = raw_input.split("://", 1)[1]

            outer = None
            encrypted_blob = None
            decoded_outer = cls._base64_decode_safe(raw_input)
            with contextlib.suppress(Exception):
                outer = json.loads(decoded_outer.decode("utf-8"))
                encrypted_blob = cls._base64_decode_safe(outer["encryptedLockedConfig"])
            if outer is None or encrypted_blob is None:
                # VLESS variant: the outer payload is a JSON header plus the
                # encrypted blob split between a base64 value and raw bytes.
                outer, encrypted_blob = cls._split_blob_outer(decoded_outer)
            if outer is None or not encrypted_blob:
                return None

            decrypted_outer = cls._aes_cfb_decrypt(encrypted_blob, DTConstants.KEY_256, DTConstants.IV)
            unpacked_outer = cls._unpack_first(decrypted_outer)

            if "EncryptedLockedConfig" in unpacked_outer:
                decrypted_inner = cls._aes_cfb_decrypt(unpacked_outer["EncryptedLockedConfig"], DTConstants.KEY_192, DTConstants.IV)
                unpacked_inner = cls._unpack_first(decrypted_inner)
                unpacked_outer["EncryptedLockedConfig"] = cls._clean_encrypted(unpacked_inner, DTConstants.KEY_192, DTConstants.IV)

            outer["encryptedLockedConfig"] = unpacked_outer
            normalized = cls._normalize_for_json(outer)

            return (
                f"┌───────────────\n│𝗦𝗣 - 𝗗𝗘𝗖𝗢𝗗𝗘 (.dark)\n│𝗗𝗘𝗩𝗘𝗟𝗢𝗣𝗘𝗥 : https://bit.ly/3TOrZEu\n├───────────────\n"
                f"{_format_top_level_json(normalized)}\n\n"
                f"├───────────────\n│[۞] 𝗚𝗥𝗢𝗨𝗣 : @CodeBreakersHub\n│[۞] 𝗖𝗛𝗔𝗡𝗡𝗘𝗟 : @GhostDeve\n└───────────────\n"
            )
            
        return None


def run(file_bytes: bytes) -> Optional[str]:
    """Entry point for seamless integration."""
    return DTDecryptor.execute(file_bytes)


def main() -> int:
    """CLI: python SCRIPT.py \"archivo.ext\"."""
    import sys
    from pathlib import Path

    # Evita errores al imprimir los caracteres Unicode del formato de salida,
    # especialmente en terminales de Windows con una codificación heredada.
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8")
        except (AttributeError, ValueError):
            pass

    if len(sys.argv) != 2:
        print(f'Uso: {Path(sys.argv[0]).name} \"archivo\"', file=sys.stderr)
        return 2

    input_path = Path(sys.argv[1])
    if not input_path.is_file():
        print(f"No se encontró el archivo: {input_path}", file=sys.stderr)
        return 2

    try:
        file_bytes = input_path.read_bytes()
    except OSError as exc:
        print(f"No se pudo leer el archivo: {exc}", file=sys.stderr)
        return 2

    try:
        result = run(file_bytes)
    except Exception as exc:
        print(f"Error al ejecutar el decodificador: {exc}", file=sys.stderr)
        return 1

    if not result:
        print("No se pudo decodificar el archivo o su formato no es válido.", file=sys.stderr)
        return 1

    print(result)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


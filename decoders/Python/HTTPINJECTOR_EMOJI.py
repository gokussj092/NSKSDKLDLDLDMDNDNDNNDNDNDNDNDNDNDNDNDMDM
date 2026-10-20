#!/usr/bin/env python3
"""HTTP Injector 6.5.0/244: emojis -> clave cloud -> configuración descifrada.

Necesita HTTPINJECTOR_CLOUD.py y HTTPINJECTOR.py en el mismo directorio.
--key-only resuelve la referencia sin contactar al servidor.
"""
import argparse
import base64
import binascii
import sys

if __package__:
    from . import HTTPINJECTOR_CLOUD as cloud
else:
    import HTTPINJECTOR_CLOUD as cloud

PREFIX = "💉"
SUFFIX = "🚀"
OFFSET = 128467  # 0x1F5D3, constante real del codec; NO 0x1F600.


class EmojiError(cloud.CloudError):
    pass


def decode_emoji_key(token):
    if isinstance(token, bytes):
        try:
            token = token.decode("utf-8-sig")
        except UnicodeError as exc:
            raise EmojiError("El archivo de emojis no es texto UTF-8.") from exc
    if not isinstance(token, str) or len(token) > 1024:
        raise EmojiError("Se esperaba una secuencia corta de emojis.")
    token = token.strip()
    if not token.startswith(PREFIX) or not token.endswith(SUFFIX):
        raise EmojiError("La secuencia debe empezar con 💉 y terminar con 🚀.")
    encoded = []
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="
    for index, symbol in enumerate(token[1:-1]):
        value = ord(symbol) - OFFSET
        if not 0 <= value < 128 or chr(value) not in alphabet:
            raise EmojiError(f"Emoji inválido en posición {index + 1}: U+{ord(symbol):04X}.")
        encoded.append(chr(value))
    encoded = "".join(encoded)
    try:
        raw = base64.b64decode(encoded, validate=True)
    except (ValueError, binascii.Error) as exc:
        raise EmojiError("Los emojis no representan Base64 estándar válido.") from exc
    # El exportador utiliza Base64 NO_WRAP con padding: no reparar entradas.
    if not raw or base64.b64encode(raw).decode("ascii") != encoded:
        raise EmojiError("Base64 de emojis vacío o no canónico; vuelve a copiar la exportación.")
    try:
        key = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise EmojiError(f"Los emojis producen UTF-8 inválido en el byte {exc.start}; "
                         "vuelve a copiar la secuencia original.") from exc
    try:
        return cloud.parse_reference(key)
    except cloud.CloudError as exc:
        raise EmojiError("Los emojis no producen una clave cloud válida.") from exc


def encode_emoji_key(key):
    """Operación inversa del exportador, útil para verificar el codec sin Android."""
    key = cloud.parse_reference(key)
    encoded = base64.b64encode(key.encode("utf-8")).decode("ascii")
    return PREFIX + "".join(chr(OFFSET + ord(char)) for char in encoded) + SUFFIX


def decode_emoji(token, audit=None, *, timeout=20):
    key = decode_emoji_key(token)
    document = cloud.decode_cloud(key, audit, timeout=timeout)
    if audit is not None:
        audit["transport"] = "http-injector-emoji"
        audit["emoji_codec"] = "codepoint - 128467 -> Base64 estándar -> UTF-8 -> clave cloud"
    return document


def run(file_bytes):
    try:
        return cloud.ehi._format_ehi_document(decode_emoji(file_bytes)).replace("(.ehi)", "(emoji)", 1)
    except cloud.CloudError:
        return None


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", help="secuencia 💉…🚀 o archivo de texto UTF-8")
    parser.add_argument("--key-only", action="store_true", help="mostrar clave y URL, sin red")
    parser.add_argument("--json", action="store_true", help="JSON completo (salida predeterminada)")
    parser.add_argument("-o", "--output", help="archivo JSON de salida")
    parser.add_argument("--audit", help="informe JSON de verificaciones y transformaciones")
    args = parser.parse_args()
    try:
        cloud.validate_output_paths(args.source, None, args.output, args.audit)
        token = cloud.read_source(args.source)
        audit = {}
        if args.key_only:
            key = decode_emoji_key(token)
            document = {"config_key": key, "url": "https://ehi.link/" + key}
            audit = {"transport": "http-injector-emoji", "downloaded": False}
        else:
            document = decode_emoji(token, audit)
        cloud.write_json(document, args.output)
        if args.audit:
            cloud.write_json(audit, args.audit)
        return 0
    except (cloud.CloudError, OSError, ImportError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
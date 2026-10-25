#!/usr/bin/env python3
"""HTTP Door 5.0 .kyz: raw DES/ECB/PKCS5Padding and Java Properties XML.

The repository shares its lossless XML parser with CREEB INJECTOR. The
Termux bundler embeds those exact functions; no APK or network is required.
"""
from __future__ import annotations
import argparse
import os
from pathlib import Path
import sys
from Crypto.Cipher import DES
from Crypto.Util.Padding import unpad

# Embedded canonical CREEB Java Properties parser.
import json
import math
import re
import xml.etree.ElementTree as ET
MAX_BYTES = 8 * 1024 * 1024
MAX_DEPTH = 64

class DecodeError(ValueError):
    """Sanitized error with no configuration data or password hashes."""

def _validate(value):
    pending, count = [(value, 0)], 0
    while pending:
        item, depth = pending.pop()
        count += 1
        if depth > MAX_DEPTH or count > 1_000_000:
            raise DecodeError("Complejidad superior al límite.")
        if isinstance(item, dict):
            pending.extend((v, depth + 1) for v in item.values())
            pending.extend((k, depth + 1) for k in item)
        elif isinstance(item, list):
            pending.extend((v, depth + 1) for v in item)
        elif isinstance(item, float) and not math.isfinite(item):
            raise DecodeError("Número fuera de rango.")
        elif isinstance(item, str):
            item.encode("utf-8")
    return value

def decode_properties(xml: bytes) -> dict:
    """Preserve all XML entries and source, plus Java's last-value-wins map."""
    if not xml or len(xml) > MAX_BYTES:
        raise DecodeError("XML vacío o demasiado grande.")
    try:
        text = xml.decode("utf-8")
        # The standard Java DTD is a format marker, never a network request.
        # Disallow entities and every other DOCTYPE, including internal subsets.
        if re.search(r"<!\s*ENTITY", text, re.I):
            raise ValueError
        cleaned = re.sub(r'<!DOCTYPE\s+properties\s+SYSTEM\s+[\'"]http://java\.sun\.com/dtd/properties\.dtd[\'"]\s*>', "", text)
        if re.search(r"<!\s*DOCTYPE", cleaned, re.I):
            raise ValueError
        # JDK/Android Properties XML can emit separate UTF-16 surrogate numeric
        # references for supplementary characters. Combine only valid pairs;
        # keep raw_xml exact, and reject isolated surrogate references via ET.
        pieces, position, high = [], 0, None
        for match in re.finditer(r"&#(?:x([0-9a-fA-F]{1,6})|([0-9]{1,7}));", cleaned):
            number = int(match[1], 16) if match[1] else int(match[2])
            if high and high[0].end() == match.start() and 0xdc00 <= number <= 0xdfff:
                pieces.append(cleaned[position:high[0].start()])
                pieces.append(f"&#{0x10000 + ((high[1] - 0xd800) << 10) + number - 0xdc00};")
                position, high = match.end(), None
            else:
                high = (match, number) if 0xd800 <= number <= 0xdbff else None
        pieces.append(cleaned[position:])
        cleaned = "".join(pieces)
        root = ET.fromstring(cleaned)
        if (root.tag != "properties" or set(root.attrib) - {"version"} or
                root.attrib.get("version", "1.0") != "1.0" or (root.text or "").strip()):
            raise ValueError
        entries, properties = [], {}
        for node in root:
            if len(node) or (node.tail or "").strip():
                raise ValueError
            if node.tag == "comment" and not node.attrib:
                continue
            if node.tag != "entry" or set(node.attrib) != {"key"}:
                raise ValueError
            key, value = node.attrib["key"], node.text or ""
            entries.append({"key": key, "value": value})
            properties[key] = value
        if not entries:
            raise ValueError
        return _validate({"format": "creeb-des-properties", "properties": properties,
                          "entries": entries, "raw_xml": text})
    except (ValueError, UnicodeError, ET.ParseError, RecursionError) as exc:
        raise DecodeError("XML Java Properties inválido.") from exc

def render(value: dict) -> str:
    try:
        output = json.dumps(_validate(value), ensure_ascii=False, indent=2, allow_nan=False)
        if len(output.encode("utf-8")) > MAX_BYTES:
            raise DecodeError("Salida superior a 8 MiB.")
        return output
    except (UnicodeError, RecursionError) as exc:
        raise DecodeError("JSON de salida inválido.") from exc


# ConfigParser.KEY_PASSWORD = "cinbdf665$4"; DESKeySpec takes eight bytes.
DES_KEY = b"cinbdf66"


def decode(data: bytes) -> dict:
    if not isinstance(data, bytes) or not data or len(data) > MAX_BYTES:
        raise DecodeError("Entrada vacía o superior a 8 MiB.")
    if len(data) % 8:
        raise DecodeError("Archivo .kyz incompleto.")
    try:
        xml = unpad(DES.new(DES_KEY, DES.MODE_ECB).decrypt(data), 8)
        result = decode_properties(xml)
        result["format"] = "http-door-des-properties"
        return result
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise DecodeError("Archivo inválido o incompatible con HTTP Door 5.0.") from exc


def run(data: bytes) -> str:
    return render(decode(data))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("file", help="Archivo .kyz o - para stdin")
    parser.add_argument("--output", "-o", type=Path, help="Guardar JSON privado sin sobrescribir")
    args = parser.parse_args()
    try:
        if args.file == "-":
            data = sys.stdin.buffer.read(MAX_BYTES + 1)
        else:
            with Path(args.file).open("rb") as stream:
                data = stream.read(MAX_BYTES + 1)
        output = run(data) + "\n"
        if args.output:
            with os.fdopen(os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "w", encoding="utf-8") as stream:
                stream.write(output)
        else:
            sys.stdout.write(output)
        return 0
    except (OSError, ValueError):
        print("No se pudo abrir el .kyz o guardar el JSON completo; no se sobrescriben archivos.", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

"""CREEB INJECTOR 38.0 (40): raw DES/Java Properties and JSON profile bundles.

Offline, one confirmed format key. Custom password hashes and HWID are stored
import locks and are preserved; no password or device identity is needed here.
"""
from __future__ import annotations
import json
import math
import re
import xml.etree.ElementTree as ET
from Crypto.Cipher import DES
from Crypto.Util.Padding import unpad

MAX_BYTES = 8 * 1024 * 1024
MAX_DEPTH = 64
BUNDLE_TYPE = "creeb_profile_bundle"
# ConfigParser$1.toString() produces CREEBINJECT. DESKeySpec uses the first 8.
DES_KEY = b"CREEBINJ"


class DecodeError(ValueError):
    """Sanitized error with no configuration data or password hashes."""


def _unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise DecodeError("Claves JSON duplicadas.")
        result[key] = value
    return result


def _constant(_value):
    raise DecodeError("Número JSON no finito.")


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


def _bundle(value):
    if (not isinstance(value, dict) or value.get("type") != BUNDLE_TYPE or
            type(value.get("version")) is not int or value["version"] != 1 or
            not isinstance(value.get("profiles"), list) or not value["profiles"]):
        raise DecodeError("Bundle CREEB incompatible.")
    for profile in value["profiles"]:
        if (not isinstance(profile, dict) or not isinstance(profile.get("prefs"), dict) or
                any(not isinstance(profile.get(k), str) for k in ("id", "name", "hostPort")) or
                type(profile.get("tunnelType")) is not int):
            raise DecodeError("Perfil CREEB incompatible.")
    if "security" in value and not isinstance(value["security"], dict):
        raise DecodeError("Opciones de seguridad incompatibles.")
    return _validate(value)


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


def decode(data: bytes) -> dict:
    if not isinstance(data, bytes) or not data or len(data) > MAX_BYTES:
        raise DecodeError("Entrada vacía o superior a 8 MiB.")
    # New exports are plain UTF-8 JSON. An invalid JSON probe must not exclude
    # a valid raw DES block whose random first byte happens to be an ASCII '{'.
    stripped = data.lstrip()
    if stripped.startswith(b"{"):
        try:
            value = json.loads(data.decode("utf-8"), object_pairs_hook=_unique, parse_constant=_constant)
        except (ValueError, UnicodeError, RecursionError):
            if len(data) % 8:
                raise DecodeError("JSON de entrada inválido.") from None
        else:
            return _bundle(value)
    if len(data) < 8 or len(data) % 8:
        raise DecodeError("Contenedor DES incompleto.")
    try:
        xml = unpad(DES.new(DES_KEY, DES.MODE_ECB).decrypt(data), 8)
    except ValueError as exc:
        raise DecodeError("Contenido DES incompatible.") from exc
    return decode_properties(xml)


def render(value: dict) -> str:
    try:
        output = json.dumps(_validate(value), ensure_ascii=False, indent=2, allow_nan=False)
        if len(output.encode("utf-8")) > MAX_BYTES:
            raise DecodeError("Salida superior a 8 MiB.")
        return output
    except (UnicodeError, RecursionError) as exc:
        raise DecodeError("JSON de salida inválido.") from exc

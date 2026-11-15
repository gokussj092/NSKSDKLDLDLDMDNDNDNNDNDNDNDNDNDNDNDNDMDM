#!/usr/bin/env python3
"""Evidencia reproducible del bug de presentacion .ehi (direct_v2r).

Port en Python de ResultPresentation.extractStandaloneJsonObject (version con
el bug y version corregida) y de la ruta de campos de ResultPresentation.parse
+ ResultJsonDisplay.normalize. Se ejecuta SOLO sobre el fixture sintetico
(fixtures/synthetic_ehi_v2r_rawtext.txt): ningun valor real, ningun .ehi real.

Uso desde la raiz del repo:
    python analysis/com.evozi.injector/244/tools/check_display_extraction.py
Sale 0 si: el codigo con el bug devuelve solo el primer inbound (tun-inbound),
el codigo corregido no extrae documento suelto, y el parseo por campos entrega
el v2rRawJson completo (2 inbounds, 4 outbounds).
"""
import json
import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
FIXTURE = HERE.parent / "fixtures" / "synthetic_ehi_v2r_rawtext.txt"

SOURCE_LINE = re.compile(r"^\s*│\[[^]]+]\s*([^:\r\n]+):\s*(.*)$")
DECORATIVE = re.compile(r"^[\s│┌┐└┘├┤─═╔╗╚╝╠╣]+$")
DECORATED_HEADING = re.compile(
    r"(?i)^\s*│?\s*(?:SP\s*[-–]\s*DECODE|[┌└├╔╚].*|(?:Developer|Group|Channel|Créditos|Credits|Copyright)\s*:)")
DECORATION = re.compile(r"(?i)(DEVELOPER|GROUP|CHANNEL|COPYRIGHT|CREDITS|SP\s*-\s*DECODE|Aplicaci[oó]n)")
DECIMAL = re.compile(r"-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?")

EXPECTED_FIRST_INBOUND = {
    "listen": "0.0.0.0", "port": "1080", "protocol": "dokodemo-door",
    "settings": {"network": "tcp,udp", "followRedirect": True},
    "tag": "tun-inbound",
}


def balanced_object(text, start):
    depth = 0
    quote = False
    escaped = False
    for i in range(start, len(text)):
        c = text[i]
        if quote:
            if escaped:
                escaped = False
            elif c == "\\":
                escaped = True
            elif c == '"':
                quote = False
        else:
            if c == '"':
                quote = True
            elif c == "{":
                depth += 1
            elif c == "}":
                depth -= 1
                if depth == 0:
                    return text[start:i + 1]
                if depth < 0:
                    return None
    return None


def extract_buggy(text):
    """Version anterior: acepta la primera linea '{' de todo el texto."""
    offset = 0
    for line in text.split("\n"):
        if line.strip() == "{":
            pos = offset + line.index("{")
            js = balanced_object(text, pos)
            if js is not None:
                try:
                    item = json.loads(js)
                    if isinstance(item, dict):
                        return item
                except Exception:
                    pass
        offset += len(line) + 1
    return None


def extract_fixed(text):
    """Version corregida: una linea '{' dentro del valor de un campo no es un
    documento suelto. insideField se abre con una linea de campo y se cierra
    con una linea decorativa."""
    offset = 0
    inside_field = False
    for line in text.split("\n"):
        trimmed = line.strip()
        if SOURCE_LINE.match(line):
            inside_field = True
        elif DECORATIVE.match(trimmed) or DECORATED_HEADING.search(trimmed):
            inside_field = False
        if trimmed == "{" and not inside_field:
            pos = offset + line.index("{")
            js = balanced_object(text, pos)
            if js is not None:
                try:
                    item = json.loads(js)
                    if isinstance(item, dict):
                        return item
                except Exception:
                    pass
        offset += len(line) + 1
    return None


def parse_inline(value):
    t = value.strip()
    if t in ("true", "false", "null") or DECIMAL.fullmatch(t) \
            or t.startswith("{") or t.startswith("["):
        try:
            return json.loads(t)
        except Exception:
            pass
    return value


def parse_fields(text):
    obj = {}
    current_key = None
    pending_sep = ""
    for m in re.finditer(r"([^\r\n]*)(\r\n|\n|\r|$)", text):
        raw, ending = m.group(1), m.group(2)
        field = SOURCE_LINE.match(raw)
        if field:
            current_key = None
            pending_sep = ""
            key = field.group(1).strip()
            value = field.group(2).strip()
            if (not key or DECORATION.search(key) or "𝗚𝗥𝗢𝗨𝗣" in key
                    or "𝗖𝗛𝗔𝗡𝗡𝗘𝗟" in key or "𝗗𝗘𝗩𝗘𝗟𝗢𝗣𝗘𝗥" in key):
                continue
            unique = key
            n = 2
            while unique in obj:
                unique = f"{key} ({n})"
                n += 1
            obj[unique] = parse_inline(value)
            current_key = unique
            pending_sep = ending
            continue
        if current_key is None:
            continue
        if DECORATIVE.match(raw.strip()) or DECORATED_HEADING.search(raw.strip()):
            current_key = None
            pending_sep = ""
            continue
        if not raw.strip():
            pending_sep += raw + ending
            continue
        before = obj[current_key]
        prev = before if isinstance(before, str) else json.dumps(before, ensure_ascii=False)
        obj[current_key] = parse_inline(prev + pending_sep + raw)
        pending_sep = ending
    return obj


def normalize(value):
    if isinstance(value, dict):
        return {k: normalize(v) for k, v in value.items()}
    if isinstance(value, list):
        return [normalize(v) for v in value]
    if isinstance(value, str):
        t = value.strip()
        if (t.startswith("{") and t.endswith("}")) or (t.startswith("[") and t.endswith("]")):
            try:
                return normalize(json.loads(t))
            except Exception:
                pass
        return value
    return value


def main():
    text = FIXTURE.read_text(encoding="utf-8")
    failures = []

    def check(name, condition, detail=""):
        print(("PASS " if condition else "FAIL ") + name + (f" ({detail})" if detail else ""))
        if not condition:
            failures.append(name)

    buggy = extract_buggy(text)
    check("buggy devuelve solo el primer inbound",
          buggy == EXPECTED_FIRST_INBOUND,
          f"claves={list(buggy.keys()) if buggy else None}")
    fixed = extract_fixed(text)
    check("corregido no extrae documento suelto", fixed is None, f"fixed={fixed}")
    full = normalize(parse_fields(text))
    v2r = full.get("v2rRawJson")
    check("campos del perfil presentes", len(full) == 6, f"n={len(full)}")
    check("v2rRawJson es objeto completo", isinstance(v2r, dict))
    inbounds = v2r.get("inbounds", []) if isinstance(v2r, dict) else []
    outbounds = v2r.get("outbounds", []) if isinstance(v2r, dict) else []
    check("2 inbounds", len(inbounds) == 2,
          f"tags={[i.get('tag') for i in inbounds]}")
    check("4 outbounds", len(outbounds) == 4,
          f"tags={[o.get('tag') for o in outbounds]}")
    check("sin perdida: el JSON final no es solo el primer inbound",
          "listen" not in full and "tunnelType" in full)
    if failures:
        print(f"{len(failures)} comprobacion(es) fallida(s)")
        return 1
    print("Todas las comprobaciones pasaron con el fixture sintetico.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

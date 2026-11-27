#!/usr/bin/env python3
"""Sonda offline de la KDF interior n19 (HTTP Custom 8.1.5, build 942).

Prueba construcciones candidatas contra la seccion `i` del archivo
test_open_2_7xqg.hc (h=0, sin contrasena) usando el tag Poly1305 como
oraculo: un candidato es correcto solo si _dec_section no lanza
"auth failed". NO prueba contrasenas ni variantes de contrasena (eso
esta prohibido); solo construcciones estructurales derivadas de la
n15 documentada en decoders/Python/apps/HTTP_Custom/codec.py.

Control: la misma rejilla sobre drive/Test Oppen.hc (934, n15, h=0)
debe abrir con la construccion n15 documentada; si el control falla,
la sonda esta mal y nada de lo demas vale.

Uso:
  probe_n19.py --control   # solo control 934
  probe_n19.py             # control + rejilla n19 sobre test_open
  probe_n19.py --file <otro .hc>   # rejilla n19 sobre otro archivo h=0

En exito solo se imprimen las claves de nivel superior del JSON de la
seccion principal, nunca su contenido ni perfiles.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, "/home/hatch/workspace/spdecode-patch/decoders/Python")
sys.path.insert(0, "/home/hatch/workspace/spdecode-patch/decoders/Python/apps/HTTP_Custom")

import _hc_hccfg as hist
from codec import open_envelope
from crypto import native_fold, native_fold_n15

PKG = hist.PKG
VENV = "/home/hatch/workspace/http-custom-update/venv/bin/python"

CONTROL = "/home/hatch/workspace/http-custom-update/drive/Test Oppen.hc"
TARGET = "/home/hatch/workspace/user/files/test_open_2_7xqg.hc"


def section_i(env):
    sec = env.get("i")
    if not isinstance(sec, dict):
        raise hist.HCError("INVALID_MAIN_SECTION")
    return sec


def try_section(env, key, aad, label_for_skey=None):
    """Devuelve el JSON de la seccion i si la clave candidata autentica."""
    sec = section_i(env)
    skey = key if label_for_skey is None else hist._hkdf(
        key, label_for_skey, aad + b"\x00" + sec["a"].encode())
    raw = hist._dec_section(sec, skey, aad)
    return json.loads(raw.decode("utf-8"))


def n15_style(env, fold, content_label, part_label, schema=b"14",
              sched=b"n19", aad_schema=None, aad_sched=None):
    """Construccion _derive_n15 con sustituciones (esquema/schedule/labels)."""
    seed = hist._env_key(env)
    features = hist._features(env)
    build = hist._n_bytes(env)
    aad = (b"HCCFG|" + (aad_schema or schema) + b"|XCHACHA20P1305|NATIVE-HKDF-SHA256|"
           + (aad_sched or sched) + b"|" + PKG + b"|1|" + features + b"|0|" + build)
    content = fold(aad)
    key = hist._hkdf(content, seed, content_label)
    return key, aad, part_label


def n11_style(env, fold, part_label):
    """Construccion transcript+seed (n11/n12) con schedule n19."""
    seed = hist._env_key(env)
    features = hist._features(env)
    build = hist._n_bytes(env)
    transcript = b"HCCFG\0" + PKG + b"\01\0" + features + b"\0" + build + b"\0"
    ikm = fold(transcript + seed)
    info = b"app-config|n19|" + PKG + b"|1|" + features + b"|" + build
    key = hist._hkdf(ikm, seed, info)
    aad = (b"HCCFG|14|XCHACHA20P1305|NATIVE-HKDF-SHA256|n19|" + PKG
           + b"|1|" + features + b"|0|" + build)
    return key, aad, part_label


def run_grid(env, tag):
    results = []
    # --- Control n15 documentado (debe abrir Test Oppen.hc) ---
    candidates = []
    candidates.append(("control-n15-doc",) + n15_style(
        env, native_fold_n15, b"hc-config-content-v12", b"hc-config-part-v12",
        schema=b"12", sched=b"n15"))
    # --- A: estilo n15 con sustituciones 14/n19/942 ---
    for fold_name, fold in (("fold-n15", native_fold_n15), ("fold-v4", native_fold)):
        for cl in (b"hc-config-content-v12", b"hc-config-content-v13",
                   b"hc-config-content-v14"):
            for pl in (b"hc-config-part-v12", b"hc-config-part-v13",
                       b"hc-config-part-v14", None):
                name = f"A-{fold_name}-{cl.decode()[-3:]}-part-{pl.decode()[-3:] if pl else 'direct'}"
                candidates.append((name,) + n15_style(env, fold, cl, pl))
    # --- B: estilo transcript n11/n12 con n19 ---
    for fold_name, fold in (("fold-n15", native_fold_n15), ("fold-v4", native_fold)):
        for pl in (b"hc-config-part-v12", b"hc-config-part-v13",
                   b"hc-config-part-v14", None):
            name = f"B-{fold_name}-part-{pl.decode()[-3:] if pl else 'direct'}"
            candidates.append((name,) + n11_style(env, fold, pl))
    # --- C: AAD con esquema viejo (12/n15) pero build 942 ---
    candidates.append(("C-aad12-n15-build942",) + n15_style(
        env, native_fold_n15, b"hc-config-content-v12", b"hc-config-part-v12",
        aad_schema=b"12", aad_sched=b"n15"))
    candidates.append(("C-aad14-n15-build942",) + n15_style(
        env, native_fold_n15, b"hc-config-content-v12", b"hc-config-part-v12",
        aad_schema=b"14", aad_sched=b"n15"))

    for name, key, aad, part_label in candidates:
        try:
            main = try_section(env, key, aad, part_label)
            print(f"[{tag}] HIT  {name}  -> main keys: {sorted(main.keys()) if isinstance(main, dict) else type(main).__name__}")
            results.append((name, True))
        except Exception:
            results.append((name, False))
    hits = [n for n, ok in results if ok]
    print(f"[{tag}] {len(hits)}/{len(results)} aciertos: {hits or 'ninguno'}")
    return hits


def main(argv=None):
    p = argparse.ArgumentParser(description="Sonda offline KDF interior n19.")
    p.add_argument("--control", action="store_true", help="solo control 934")
    p.add_argument("--file", default=TARGET, help="archivo .hc h=0 a probar")
    args = p.parse_args(argv)

    env_c = open_envelope(Path(CONTROL).read_bytes())
    print(f"control: b={env_c.get('b')} e={env_c.get('e')} n={env_c.get('n')} h={env_c.get('h')}")
    hits_c = run_grid(env_c, "control-934")
    if "control-n15-doc" not in hits_c:
        print("CONTROL FALLO: la sonda no reproduce la n15 documentada. Parar.")
        return 2
    print("CONTROL OK: la sonda reproduce la n15 documentada.")
    if args.control:
        return 0
    env = open_envelope(Path(args.file).read_bytes())
    print(f"objetivo: {args.file}  b={env.get('b')} e={env.get('e')} n={env.get('n')} h={env.get('h')}")
    if env.get("h"):
        print("El archivo lleva contrasena (h=1): la sonda no prueba contrasenas.")
        return 3
    hits = run_grid(env, "n19-815")
    return 0 if hits else 1


if __name__ == "__main__":
    raise SystemExit(main())

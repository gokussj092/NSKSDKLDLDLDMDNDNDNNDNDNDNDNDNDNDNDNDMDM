#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""SNI Tunnel - V2Ray VPN Client (com.asnly.snitunnel) 1.3.0 — parseo de
archivos de configuración y de enlaces de texto, formato de proveedor
de SP-DECODE.

La app importa archivos de texto (parseDocument): lista de enlaces,
blob Base64 o YAML Clash, con sourceKind "manual" e ids UUID aleatorios.
También acepta enlaces de texto por intent (AndroidManifest):

  vmess:// vless:// trojan:// ss:// hy2:// hysteria2:// tuic:// socks://
      enlaces estándar; SP-DECODE ya los decodifica y aquí se parsean
      con el mismo código que SNI_Tunnel.py.
  v2ray://
      alias genérico de la app para un enlace vmess (JSON en Base64).
  snitunnel://connect | disconnect | toggle | open
      enlaces de control de la app (no llevan perfil).
  snitunnel://add/<enlace-de-config> | snitunnel://add/<url-https>
      añade un perfil o una suscripción (la URL va codificada).
  v2rc://
      enlace con contraseña. Su descifrado vive en el Dart AOT
      (package sni_ui) y NO se puede reproducir por análisis estático:
      se reporta como UNSUPPORTED_SEALED, nunca se inventa.
  v2rcloud://
      cloud link: el servicio en la nube aplica límites de descarga y
      caducidad sin ver la config; el descifrado es Dart-side. Se
      reporta como UNSUPPORTED_CLOUD.
  snitheme://
      enlace de tema (tema de la app), no es un perfil.

Solo biblioteca estándar de Python 3.10+. Reutiliza los parsers de
SNI_Tunnel.py (mismo directorio).
"""

import json
import os
import re
import sys
import urllib.parse
import uuid

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import SNI_Tunnel  # noqa: E402

CONTROL_ACTIONS = ("connect", "disconnect", "toggle", "open")


def parse_document(text):
    """Igual que SubscriptionContent.parseDocument (sourceKind manual)."""
    profiles, failures = SNI_Tunnel.parse_subscription_body(
        text, subscription_id="file", url="https://file.invalid")
    out = []
    for p in profiles:
        p = dict(p)
        p["id"] = str(uuid.uuid4())
        p["sourceKind"] = "manual"
        p["subscriptionId"] = "file"
        out.append(p)
    return {
        "url": "https://file.invalid",
        "subscriptionId": "file",
        "profiles": out,
        "failures": failures,
        "sourceKind": "manual",
    }


def parse_v2ray(link):
    """v2ray://<base64 JSON vmess> (alias genérico de la app)."""
    body = link[len("v2ray://"):]
    try:
        data = json.loads(SNI_Tunnel._b64d(body).decode("utf-8"))
    except Exception:
        return None
    if not isinstance(data, dict) or not data.get("add"):
        return None
    return SNI_Tunnel.parse_vmess("vmess://" + body)


def parse_snitunnel(link):
    """Enlaces de control snitunnel:// (AndroidManifest, MainActivity)."""
    rest = link[len("snitunnel://"):]
    host, _, tail = rest.partition("/")
    host = host.lower()
    if host in CONTROL_ACTIONS:
        return {"scheme": "snitunnel", "action": host}
    if host == "add":
        embedded = urllib.parse.unquote(tail)
        result = {"scheme": "snitunnel", "action": "add", "url": embedded}
        if embedded.lower().startswith("https://"):
            result["kind"] = "subscription"
        else:
            p = SNI_Tunnel.parse_link(embedded)
            if p is not None:
                result["kind"] = "profile"
                result["profile"] = p
            else:
                result["kind"] = "unknown"
        return result
    return {"scheme": "snitunnel", "action": "unknown", "host": host}


def parse_text_link(text):
    """Parsea un enlace de texto que la app acepta por intent."""
    text = text.strip()
    low = text.lower()
    if low.startswith("snitunnel://"):
        return parse_snitunnel(text)
    if low.startswith("v2rc://"):
        return {
            "scheme": "v2rc", "status": "UNSUPPORTED_SEALED",
            "note": "Enlace con contraseña; el descifrado vive en el "
                    "Dart AOT (package sni_ui) y no se puede reproducir "
                    "por análisis estático. Se necesita una captura en "
                    "vivo o el enlace original sin sellar.",
        }
    if low.startswith("v2rcloud://"):
        return {
            "scheme": "v2rcloud", "status": "UNSUPPORTED_CLOUD",
            "note": "Cloud link cifrado; el servicio en la nube aplica "
                    "límites de descarga y caducidad sin ver la config. "
                    "El descifrado es Dart-side y no se puede reproducir "
                    "por análisis estático.",
        }
    if low.startswith("snitheme://"):
        return {"scheme": "snitheme", "kind": "theme",
                "note": "Enlace de tema de la app, no es un perfil."}
    if low.startswith("v2ray://"):
        p = parse_v2ray(text)
        if p is None:
            return {"scheme": "v2ray", "status": "PARSE_FAILED"}
        return {"scheme": "v2ray", "kind": "profile", "profile": p}
    p = SNI_Tunnel.parse_link(text)
    if p is not None:
        return {"scheme": p["type"], "kind": "profile", "profile": p}
    return {"scheme": "unknown", "status": "PARSE_FAILED"}


def decode(data, is_file=False):
    """Entrada estilo SP-DECODE: texto o ruta de archivo -> dict JSON."""
    if is_file:
        with open(data, encoding="utf-8", errors="replace") as f:
            text = f.read()
        result = parse_document(text)
        result["file"] = data
        return result
    text = data.strip()
    if "\n" in text or "://" not in text:
        return parse_document(text)
    result = parse_text_link(text)
    if result.get("kind") == "profile":
        result["profiles"] = [result.pop("profile")]
        result["failures"] = 0
    return result


def run(path=None, text=None, output=None):
    if path is not None:
        result = decode(path, is_file=True)
    elif text is not None:
        result = decode(text)
    else:
        raise ValueError("Falta un archivo o un enlace de texto.")
    if output:
        with open(output, "w", encoding="utf-8") as f:
            json.dump(result, f, ensure_ascii=False, indent=2)
    return result


# ---------------------------------------------------------------- CLI / self-test


def _self_test():
    import base64
    ok = total = 0

    def check(name, cond):
        nonlocal ok, total
        total += 1
        if cond:
            ok += 1
        else:
            print("FAIL:", name)

    vless = ("vless://aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee@vl.example.com"
             ":443?encryption=none&security=tls&sni=vl.example.com#VL-1")
    trojan = "trojan://secreto@tj.example.com:443?sni=tj.example.com#TJ-1"

    # 1. Documento plano
    r = parse_document(vless + "\n" + trojan + "\n")
    check("doc plano: 2 perfiles", len(r["profiles"]) == 2)
    check("doc plano: manual", all(
        p["sourceKind"] == "manual" for p in r["profiles"]))
    check("doc plano: uuid v4", all(
        re.match(r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab]"
                 r"[0-9a-f]{3}-[0-9a-f]{12}$", p["id"])
        for p in r["profiles"]))

    # 2. Documento Base64
    blob = base64.b64encode((vless + "\n" + trojan).encode()).decode()
    r2 = parse_document(blob)
    check("doc b64: 2 perfiles", len(r2["profiles"]) == 2)

    # 3. Documento Clash YAML
    clash = """
proxies:
  - name: CL-1
    type: vmess
    server: cl.example.com
    port: 443
    uuid: 22222222-3333-4444-5555-666666666666
    tls: true
    network: ws
    ws-path: /clash
"""
    r3 = parse_document(clash)
    check("doc clash: 1 perfil", len(r3["profiles"]) == 1)
    check("doc clash: vmess", r3["profiles"][0]["type"] == "vmess")

    # 4. snitunnel://add con enlace embebido
    add = "snitunnel://add/" + urllib.parse.quote(vless, safe="")
    r4 = parse_text_link(add)
    check("snitunnel add: action", r4["action"] == "add")
    check("snitunnel add: profile", r4["kind"] == "profile"
          and r4["profile"]["server"] == "vl.example.com")
    add_sub = "snitunnel://add/https%3A%2F%2Fexample.com%2Fsub"
    r5 = parse_text_link(add_sub)
    check("snitunnel add: subscription", r5["kind"] == "subscription"
          and r5["url"] == "https://example.com/sub")
    for action in ("connect", "disconnect", "toggle", "open"):
        r6 = parse_text_link("snitunnel://" + action)
        check("snitunnel " + action, r6["action"] == action)

    # 5. v2rc / v2rcloud / snitheme
    r7 = parse_text_link("v2rc://abc123")
    check("v2rc sellado", r7["status"] == "UNSUPPORTED_SEALED")
    r8 = parse_text_link("v2rcloud://xyz")
    check("v2rcloud cloud", r8["status"] == "UNSUPPORTED_CLOUD")
    r9 = parse_text_link("snitheme://dark")
    check("snitheme tema", r9["kind"] == "theme")

    # 6. v2ray:// (vmess JSON en Base64)
    vmess = {"v": "2", "ps": "V2-1", "add": "v2.example.com",
             "port": "443", "id": "33333333-4444-5555-6666-777777777777",
             "aid": "0", "net": "tcp", "tls": "tls"}
    r10 = parse_text_link("v2ray://" + base64.b64encode(
        json.dumps(vmess).encode()).decode())
    check("v2ray vmess", r10["kind"] == "profile"
          and r10["profile"]["server"] == "v2.example.com")

    # 7. enlace estándar directo
    r11 = parse_text_link(trojan)
    check("trojan directo", r11["kind"] == "profile"
          and r11["profile"]["type"] == "trojan")
    r12 = parse_text_link("foo://bar")
    check("desconocido -> PARSE_FAILED", r12["status"] == "PARSE_FAILED")

    print("SELF-TEST %d/%d" % (ok, total))
    return ok == total


def main(argv):
    import argparse
    ap = argparse.ArgumentParser(
        description="SNI Tunnel 1.3.0: parsea archivos de configuración y "
                    "enlaces de texto (snitunnel://, v2rc://, v2rcloud://, "
                    "v2ray:// y enlaces estándar).")
    ap.add_argument("--text", help="Enlace de texto a parsear")
    ap.add_argument("--stdin", action="store_true")
    ap.add_argument("-o", "--output")
    ap.add_argument("--self-test", action="store_true")
    ap.add_argument("file", nargs="?")
    args = ap.parse_args(argv)
    if args.self_test:
        sys.exit(0 if _self_test() else 1)
    if args.text is not None:
        result = run(text=args.text, output=args.output)
    elif args.stdin:
        result = run(text=sys.stdin.read(), output=args.output)
    elif args.file:
        result = run(path=args.file, output=args.output)
    else:
        ap.print_help()
        sys.exit(2)
    if not args.output:
        print(json.dumps(result, ensure_ascii=False, indent=2))
    else:
        n = len(result.get("profiles", []))
        print("OK: %d perfiles, %d fallos" % (n, result.get("failures", 0)))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

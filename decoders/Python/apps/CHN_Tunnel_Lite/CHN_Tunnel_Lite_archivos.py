#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
CHN TUNNEL LITE — archivos de configuracion para SP-DECODE
==========================================================
App: CHN TUNNEL LITE (com.chntunnel.lite), version 1.4 (versionCode 14).

Formatos propios (verificados en el DEX, clases4.dex):
  1. Archivos .js / .rj
     Contenido: el cifrado modo 0 (ver CHN_Tunnel_Lite.py) del catalogo
     JSON completo, exactamente igual que el cuerpo del catalogo en vivo.
     La app lo importa desde el selector de archivos
     (CHNTunnelLiteMain.onActivityResult): descifra con modo 0, lee
     "Version" y lo compara con la del catalogo guardado; si es mas
     nuevo guarda el texto crudo como "a.rlb" dentro de un zip llamado
     "classes.dex" en filesDir y muestra "Update Success!"; si no,
     "Already Updated!". Si el nombre no termina en .js o .rj:
     "File name must end with .js or .rj".
  2. Enlaces chntunnellite://<cifrado modo 0>
     El cifrado es de UN SOLO objeto Network en JSON (no del catalogo
     completo). Se pega en la caja de texto de la app (Lic/Lkc.onClick):
       - si el JSON tiene "Lock": true -> "You cannot share the lock
         config." (la app rechaza importar configuraciones bloqueadas).
       - si tiene "isSetExpiry": true, la app comprueba "Expiry" y si
         esta vencido: "The config you imported is expired."
       - si tiene "isPinEnabled": true, la app pide el PIN
         ("Network Pin Code") y lo compara con "NetworkPinCode".
       - si no, guarda la red en custom_payload.json (ver 3) y muestra
         "Import Success!".
     No hay intent-filter en el manifest para este esquema: solo se
     puede pegar dentro de la app, no abrir desde el navegador.
  3. custom_payload.json (filesDir)
     Contenido: el cifrado modo 0 de un JSONArray con las redes
     importadas por enlace. Cada entrada es un objeto Network en JSON.
  4. classes.dex (filesDir) — almacenamiento interno del catalogo
     Es un ZIP que contiene "a.rlb": el texto crudo (cifrado modo 0)
     del catalogo importado por .js/.rj.

Tambien abre enlaces v2ray estandar que la app genera (vmess://,
vless://) al compartir, pero esos ya los cubre SP-DECODE de forma
generica y no son formato propio de CHN.

NO hay formato .sks en esta app.

Uso:
    python3 CHN_Tunnel_Lite_archivos.py archivo.js
    python3 CHN_Tunnel_Lite_archivos.py archivo.rj
    python3 CHN_Tunnel_Lite_archivos.py --link "chntunnellite://..."
    python3 CHN_Tunnel_Lite_archivos.py --link "chntunnellite://..." --pin 1234
    python3 CHN_Tunnel_Lite_archivos.py custom_payload.json
    python3 CHN_Tunnel_Lite_archivos.py classes.dex
    python3 CHN_Tunnel_Lite_archivos.py red.json --build-link
    python3 CHN_Tunnel_Lite_archivos.py catalogo.json --build-js salida.js
    python3 CHN_Tunnel_Lite_archivos.py --self-test

Solo biblioteca estandar de Python 3. Sin dependencias.
"""

import argparse
import datetime
import json
import os
import sys
import zipfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import CHN_Tunnel_Lite as core

SCHEME = "chntunnellite://"


# ------------------------------------------------------------- decodificadores

def open_catalog_cipher(text):
    """Descifra un texto modo 0 que contiene el catalogo JSON completo.
    Devuelve (raw, readable, fails)."""
    raw = core.decrypt_catalog_body(text)
    readable, fails = core.readable_catalog(raw)
    return raw, readable, fails


def open_js_rj(path):
    """Abre un archivo .js / .rj (cifrado modo 0 del catalogo)."""
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        text = f.read()
    return open_catalog_cipher(text)


def open_classes_dex(path):
    """Abre el zip filesDir/classes.dex y descifra su a.rlb."""
    with zipfile.ZipFile(path) as z:
        names = z.namelist()
        if "a.rlb" not in names:
            raise ValueError("el zip no contiene a.rlb (contiene: %s)"
                             % ", ".join(names))
        text = z.read("a.rlb").decode("utf-8", "ignore")
    return open_catalog_cipher(text)


def open_custom_payload(path):
    """Abre custom_payload.json: cifrado modo 0 de un JSONArray de redes.
    Devuelve la lista de redes legibles."""
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        text = f.read().strip()
    plain = core.decrypt_mode0(text)
    if plain is None:
        raise ValueError("DECRYPT_FAILED: custom_payload.json no abre "
                         "con modo 0")
    arr = json.loads(plain.decode("utf-8"))
    if not isinstance(arr, list):
        raise ValueError("custom_payload.json no contiene un JSONArray")
    out, fails = [], []
    for i, net in enumerate(arr):
        readable, f = core.readable_catalog({"Networks": [net]})
        out.append(readable["Networks"][0])
        fails.extend("red[%d].%s" % (i, x) for x in f)
    return out, fails


def check_expiry(network):
    """Comprueba isSetExpiry/Expiry como hace la app (u72.h).
    Devuelve (expired: bool|None, detalle). None = no se pudo verificar
    el formato de la fecha."""
    if not network.get("isSetExpiry"):
        return False, "sin caducidad"
    expiry = network.get("Expiry", "")
    if not expiry:
        return None, "isSetExpiry=true pero sin campo Expiry"
    # Formatos probables: ISO (2026-12-31), unix ms o unix s.
    try:
        if isinstance(expiry, (int, float)):
            ts = float(expiry)
            dt = datetime.datetime.fromtimestamp(
                ts / 1000.0 if ts > 1e12 else ts)
        else:
            s = str(expiry).strip()
            if s.isdigit():
                ts = float(s)
                dt = datetime.datetime.fromtimestamp(
                    ts / 1000.0 if ts > 1e12 else ts)
            else:
                dt = datetime.datetime.fromisoformat(s.replace("Z", "+00:00"))
                if dt.tzinfo is not None:
                    dt = dt.replace(tzinfo=None)
        now = datetime.datetime.now()
        return (dt < now), "Expiry=%s (ahora %s)" % (expiry, now.date())
    except Exception:
        return None, "formato de Expiry no reconocido: %r" % (expiry,)


def open_link(link, pin=None):
    """Abre un enlace chntunnellite://<modo 0 de un objeto Network>.
    Devuelve (network_legible, estado, detalle).
    estado: OK | LOCKED | EXPIRED | PIN_REQUIRED | PIN_WRONG | FAIL"""
    if not link.startswith(SCHEME):
        raise ValueError("el enlace debe empezar por %s" % SCHEME)
    cipher = link[len(SCHEME):].strip()
    plain = core.decrypt_mode0(cipher)
    if plain is None:
        return None, "FAIL", "el cifrado del enlace no abre con modo 0"
    try:
        network = json.loads(plain.decode("utf-8"))
    except Exception as e:
        return None, "FAIL", "el enlace no contiene un JSON valido: %s" % e
    if network.get("Lock") is True:
        return network, "LOCKED", "Lock=true: la app rechaza compartir " \
                                   "esta configuracion"
    expired, detail = check_expiry(network)
    if expired:
        return network, "EXPIRED", detail
    if network.get("isPinEnabled") is True:
        expected = network.get("NetworkPinCode", "")
        if isinstance(expected, str) and expected:
            # NetworkPinCode puede venir cifrado en modo 0.
            dec = core.decrypt_mode0(expected)
            if dec is not None:
                expected = dec.decode("utf-8", "replace")
        if pin is None:
            return network, "PIN_REQUIRED", \
                "isPinEnabled=true: falta el PIN (--pin)"
        if str(pin) != str(expected):
            return network, "PIN_WRONG", "el PIN no coincide"
    readable, fails = core.readable_catalog({"Networks": [network]})
    net = readable["Networks"][0]
    if fails:
        return net, "OK", "importado con %d campos sin descifrar: %s" % (
            len(fails), ", ".join(fails[:5]))
    return net, "OK", "importado"


# --------------------------------------------------------------- generadores

def build_link(network_obj):
    """Genera chntunnellite://<modo 0> desde un objeto Network (dict)."""
    data = json.dumps(network_obj, ensure_ascii=False,
                      separators=(",", ":")).encode("utf-8")
    return SCHEME + core.encrypt_mode0(data)


def build_js(catalog_obj, out_path):
    """Genera un archivo .js/.rj (modo 0 del catalogo JSON)."""
    data = json.dumps(catalog_obj, ensure_ascii=False,
                      separators=(",", ":")).encode("utf-8")
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(core.encrypt_mode0(data))
    return out_path


# --------------------------------------------------------------------- CLI

def _print_network(net):
    print(json.dumps(net, ensure_ascii=False, indent=2))


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="CHN TUNNEL LITE: abre archivos .js/.rj, enlaces "
                    "chntunnellite://, custom_payload.json y classes.dex.")
    ap.add_argument("file", nargs="?",
                    help="archivo a abrir (.js, .rj, custom_payload.json, "
                         "classes.dex o JSON plano)")
    ap.add_argument("--link", help="enlace chntunnellite://...")
    ap.add_argument("--pin", help="PIN para enlaces con isPinEnabled")
    ap.add_argument("--output", help="guardar el resultado legible (JSON)")
    ap.add_argument("--build-link", action="store_true",
                    help="generar un enlace chntunnellite:// desde el "
                         "JSON de red dado en FILE")
    ap.add_argument("--build-js", metavar="SALIDA",
                    help="generar un archivo .js/.rj desde el JSON de "
                         "catalogo dado en FILE")
    ap.add_argument("--self-test", action="store_true",
                    help="pruebas sin red y salir")
    args = ap.parse_args(argv)

    if args.self_test:
        return 0 if self_test() else 1

    if args.build_link or args.build_js:
        if not args.file:
            ap.error("--build-link/--build-js necesitan un archivo JSON")
        with open(args.file, "r", encoding="utf-8") as f:
            obj = json.load(f)
        if args.build_link:
            print(build_link(obj))
        else:
            build_js(obj, args.build_js)
            print("Archivo generado: %s" % args.build_js)
        return 0

    if args.link:
        net, status, detail = open_link(args.link, pin=args.pin)
        print("Estado: %s — %s" % (status, detail))
        if net is not None and status in ("OK", "PIN_REQUIRED", "EXPIRED"):
            _print_network(net)
            if args.output:
                with open(args.output, "w", encoding="utf-8") as f:
                    json.dump(net, f, ensure_ascii=False, indent=2)
        return 0 if status == "OK" else 2

    if not args.file:
        ap.error("usa un archivo, --link o --self-test")

    path = args.file
    name = os.path.basename(path).lower()
    if name == "classes.dex":
        raw, readable, fails = open_classes_dex(path)
        result = readable
        print("Catalogo desde classes.dex/a.rlb — Version %s, "
              "%d servidores, %d redes"
              % (raw.get("Version"), len(raw.get("Servers", [])),
                 len(raw.get("Networks", []))))
    elif name == "custom_payload.json":
        nets, fails = open_custom_payload(path)
        result = nets
        print("custom_payload.json — %d redes importadas" % len(nets))
    else:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            text = f.read()
        stripped = text.strip()
        if stripped.startswith(SCHEME):
            net, status, detail = open_link(stripped, pin=args.pin)
            print("Estado: %s — %s" % (status, detail))
            if net is not None:
                _print_network(net)
            return 0 if status == "OK" else 2
        if stripped.startswith("{") or stripped.startswith("["):
            # JSON plano (catalogo legible exportado o red suelta).
            result = json.loads(stripped)
            fails = []
            print("JSON plano (sin cifrar)")
        else:
            raw, readable, fails = open_catalog_cipher(text)
            result = readable
            print("Catalogo desde %s — Version %s, %d servidores, "
                  "%d redes" % (name, raw.get("Version"),
                                 len(raw.get("Servers", [])),
                                 len(raw.get("Networks", []))))
    if fails:
        print("ADVERTENCIA: %d campos sin descifrar: %s"
              % (len(fails), ", ".join(fails[:10])), file=sys.stderr)
    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            json.dump(result, f, ensure_ascii=False, indent=2)
        print("Guardado en %s" % args.output)
    else:
        print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


# --------------------------------------------------------------- self-test

def self_test():
    ok = True

    def check(name, cond):
        nonlocal ok
        print(("OK   " if cond else "FAIL ") + name)
        if not cond:
            ok = False

    here = os.path.dirname(os.path.abspath(__file__))

    # 1. .js/.rj: el cuerpo de muestra abre como catalogo completo.
    sample = os.path.join(here, "catalog_sample.b64")
    if os.path.exists(sample):
        raw, readable, fails = open_js_rj(sample)
        check(".js/.rj de muestra: Version 1.49",
              raw.get("Version") == "1.49")
        check(".js/.rj de muestra: 5 servidores, 44 redes",
              len(raw.get("Servers", [])) == 5 and
              len(raw.get("Networks", [])) == 44)
        check(".js/.rj de muestra: 0 campos sin descifrar", not fails)
        check(".js/.rj de muestra: servidor 1 = SERVER-01",
              readable["Servers"][0].get("Name") == "SERVER-01")
        check(".js/.rj de muestra: 20 redes con Payload",
              sum(1 for n in readable["Networks"] if n.get("Payload")) == 20)

        # 2. Enlace chntunnellite://: ida y vuelta con una red real.
        net_raw = raw["Networks"][2]
        link = build_link(net_raw)
        check("enlace generado empieza por chntunnellite://",
              link.startswith(SCHEME))
        net, status, _ = open_link(link)
        check("enlace abierto: estado OK", status == "OK")
        check("enlace abierto: misma red",
              net.get("Name") == readable["Networks"][2].get("Name") and
              net.get("Payload") == readable["Networks"][2].get("Payload"))

        # 3. custom_payload.json: ida y vuelta.
        payload = json.dumps([net_raw, raw["Networks"][3]],
                             ensure_ascii=False, separators=(",", ":"))
        tmp = os.path.join(here, "custom_payload_test.json")
        with open(tmp, "w", encoding="utf-8") as f:
            f.write(core.encrypt_mode0(payload.encode("utf-8")))
        nets, fails2 = open_custom_payload(tmp)
        os.remove(tmp)
        check("custom_payload.json: 2 redes", len(nets) == 2)
        check("custom_payload.json: 0 fallos", not fails2)

        # 4. classes.dex (zip con a.rlb): ida y vuelta.
        tmpdex = os.path.join(here, "classes_test.dex")
        with zipfile.ZipFile(tmpdex, "w") as z:
            with open(sample, "r", encoding="utf-8") as f:
                z.writestr("a.rlb", f.read())
        raw2, _, fails3 = open_classes_dex(tmpdex)
        os.remove(tmpdex)
        check("classes.dex/a.rlb: Version 1.49",
              raw2.get("Version") == "1.49")
        check("classes.dex/a.rlb: 0 fallos", not fails3)
    else:
        print("SKIP pruebas con muestra (no esta catalog_sample.b64)")

    # 5. Enlace bloqueado / caducado / con PIN (sinteticos).
    locked = {"Name": "X", "Lock": True}
    _, status, _ = open_link(build_link(locked))
    check("enlace con Lock=true -> LOCKED", status == "LOCKED")
    expired = {"Name": "X", "isSetExpiry": True, "Expiry": "2020-01-01"}
    _, status, _ = open_link(build_link(expired))
    check("enlace caducado -> EXPIRED", status == "EXPIRED")
    pinned = {"Name": "X", "isPinEnabled": True, "NetworkPinCode": "1234"}
    _, status, _ = open_link(build_link(pinned))
    check("enlace con PIN sin --pin -> PIN_REQUIRED",
          status == "PIN_REQUIRED")
    _, status, _ = open_link(build_link(pinned), pin="0000")
    check("enlace con PIN incorrecto -> PIN_WRONG", status == "PIN_WRONG")
    _, status, _ = open_link(build_link(pinned), pin="1234")
    check("enlace con PIN correcto -> OK", status == "OK")

    print("SELF-TEST: %s" % ("TODO OK" if ok else "FALLOS"))
    return ok


if __name__ == "__main__":
    sys.exit(main())

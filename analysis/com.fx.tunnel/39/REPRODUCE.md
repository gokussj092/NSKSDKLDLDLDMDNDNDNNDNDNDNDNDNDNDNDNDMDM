# Fx Tunnel 4.8 — REPRODUCE

Entorno: Python 3.12.3 (sistema). Solo biblioteca estándar; no hace
falta venv. Sin red para los tests ni para la reproducción del
empaquetado; con red solo para el catálogo en vivo (que hoy no tiene
URL). Sin secretos: ningún comando de este archivo lleva claves,
tokens ni endpoints.

## 1. Tests del expediente (sin red)

```sh
cd analysis/com.fx.tunnel/39
python3 -m unittest discover -s tests -v
```

## 2. Self-test del script de archivos (sin red)

```sh
cd ~/workspace/catalogs/fxtunnel
python3 Fx_Tunnel_archivos.py --self-test
# {"self_test": "pass", "profiles": 5, "passed": 5, "field_counts": [15, 4, 3, 1, 2], "server_psi_entries": 22}
```

## 3. Empaquetado desde el APK (sin red; reproduce bundled.json byte por byte)

```sh
cd ~/workspace/catalogs/fxtunnel
python3 Fx_Tunnel.py --apks apks/base.apk -o /tmp/fx-repro.json
cmp /tmp/fx-repro.json bundled.json   # byte-identico (2026-11-17)
python3 Fx_Tunnel.py --apks apks/base.apk --summary
# {"Version": "10288", "Free_servers": 29, "Premium_servers": 0, "Vip_servers": 0, "Private_servers": 0, "Payloads": 1353, ...}
```

## 4. Asset server.psi (sin red; reproduce server_psi.json)

```sh
python3 Fx_Tunnel_archivos.py --psi extracted/base/assets/server.psi -o /tmp/fx-psi-rerun.json
python3 -c "import json; a=json.load(open('/tmp/fx-psi-rerun.json')); b=json.load(open('server_psi.json')); print(len(a), len(b), a==b)"
# 22 22 True
```

## 5. Catálogo en vivo (BLOQUEADO: sin URL)

```sh
python3 Fx_Tunnel.py --url <URL> --summary   # solo con la URL capturada en un telefono
```

No hay URL por defecto (`CATALOG_URL = None`); no inventar ninguna.

## 6. py_compile de los scripts

```sh
python3 -m py_compile decoders/Python/apps/Fx_Tunnel/Fx_Tunnel.py decoders/Python/apps/Fx_Tunnel/Fx_Tunnel_archivos.py
```

Los SHA-256 de los scripts y de `bundled.json` están en
`MANIFEST.json`. Los scripts operativos viven en
`~/workspace/catalogs/fxtunnel/`; las copias del staging
(`decoders/Python/apps/Fx_Tunnel/`) son byte-idénticas.

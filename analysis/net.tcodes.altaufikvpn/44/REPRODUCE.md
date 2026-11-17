# ALTAUFIK VPN 5.01 — REPRODUCE

Entorno: Python 3.12.3 (sistema). PyCryptodome en el venv
`~/workspace/http-custom-update/venv/bin/python` (verificado:
Crypto 4.4.0; el worker de nube fija pycryptodome==3.23.0, misma API
usada: `AES.new`, `unpad`). Sin red para los tests; con red para la
descarga en vivo. Sin secretos: ningún comando de este archivo lleva
claves, tokens ni endpoints distintos de los dos URLs públicas del
catálogo (que son las que la app usa y las que van en el registro
supplied).

## 1. Tests del expediente (sin red)

```sh
cd analysis/net.tcodes.altaufikvpn/44
~/workspace/http-custom-update/venv/bin/python -m unittest discover -s tests -v
```

## 2. Self-test del script operativo (sin red)

```sh
cd ~/workspace/catalogs/altaufikvpn
~/workspace/http-custom-update/venv/bin/python Altaufik_VPN.py --self-test
# {"synthetic_envelope": true, "plain_json_passthrough": true, "dead_free_body_rejected": true, "ok": true}
```

## 3. Catálogo VIP en vivo (con red; el script replica la petición de la app)

```sh
cd ~/workspace/catalogs/altaufikvpn
~/workspace/http-custom-update/venv/bin/python Altaufik_VPN.py --vip --url -o /tmp/altaufik-vip-rerun.json
cmp /tmp/altaufik-vip-rerun.json live.json   # byte-identico (2026-11-17)
~/workspace/http-custom-update/venv/bin/python Altaufik_VPN.py --vip --url --summary
# {"Version": "9.5", "Servers": 7, "Tweaks": 1458, "Payloads": 1343}
```

## 4. Endpoint gratis en vivo (con red; fallo honesto esperado)

```sh
~/workspace/http-custom-update/venv/bin/python Altaufik_VPN.py --url -o /tmp/altaufik-free-rerun.json
# exit 1: {"error": "FORMAT_ERROR", "message": "Se esperaba el contenedor OpenSSL Salted__ del catálogo."}
```

## 5. py_compile de los scripts

```sh
python3 -m py_compile decoders/Python/apps/Altaufik_VPN/Altaufik_VPN.py
```

Los SHA-256 de los scripts están en `MANIFEST.json`. El script
operativo vive en `~/workspace/catalogs/altaufikvpn/`; la copia del
staging (`decoders/Python/apps/Altaufik_VPN/`) es byte-idéntica.

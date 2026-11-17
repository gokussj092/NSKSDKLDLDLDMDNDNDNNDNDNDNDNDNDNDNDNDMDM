# REPRODUCE — ANY VPN build 40 (versionCode 40)

Entorno: Python 3.12.3 del sistema; PyCryptodome 3.23.0 para el codec y los tests.
Todos los comandos se ejecutan desde la raíz del repo (`~/workspace/spdecode-patch`).

## 1. Tests del método (sin red; `unittest`)

```sh
PYTHONPATH=/tmp/pylibs python3 analysis/com.markvpnpro.pinas/40/tests/test_method.py
python3 -m unittest discover -s analysis/com.markvpnpro.pinas/40/tests -v
```

Salida esperada: `Ran 6 tests ... OK`, exit 0.
(PyCryptodome 3.23.0 es la versión fijada en `requirements.txt` del worker y en
`decoders/Python/apps/ANY_VPN/requirements.txt`.)

## 2. Self-test del script de investigación (incluye descarga en vivo)

```sh
python3 ~/workspace/catalogs/anyvpn/ANY_VPN.py --self-test
# PASS aes roundtrip red1987 / server host vector / server user vector /
#      empty field vector / parser.a vector (ir1987) / plaintext passthrough /
#      live fetch+decrypt | Version=7.3 Servers=13 Networks=89 /
#      no download APIs in output
```

## 3. Re-corrida en vivo (reproduce live.json byte por byte)

```sh
python3 ~/workspace/catalogs/anyvpn/ANY_VPN.py --out /tmp/anyvpn_fresh.json
cmp /tmp/anyvpn_fresh.json ~/workspace/catalogs/anyvpn/live.json && echo "BYTE-IDENTICAL"
```

## 4. Codec del staging sobre el cuerpo crudo guardado

```sh
PYTHONPATH=/tmp/pylibs python3 - <<'EOF'
import importlib.util, json
spec = importlib.util.spec_from_file_location('c', 'decoders/Python/apps/ANY_VPN/codec.py')
c = importlib.util.module_from_spec(spec); spec.loader.exec_module(c)
raw = open('/home/hatch/workspace/catalogs/anyvpn/probe_1e760370dff563b8fa00.bin', 'rb').read()
obj = c.decode_catalog(raw)
live = json.load(open('/home/hatch/workspace/catalogs/anyvpn/live.json'))
assert obj == live and 'config_url' not in obj and 'account_api' not in obj
print('codec staging == live.json; Version', obj['Version'], len(obj['Servers']), len(obj['Networks']))
EOF
```

## 5. Tests del repo contra el codec nuevo

```sh
# Árbol mínimo en /tmp/anytest (ver REPORT.md): 12/13 OK, 1 skipped (sin Java).
# El único fallo es el esperado: test_complete_catalog_preserves_names_plain_certificates_and_flags
# espera config_url/account_api en la salida; el codec nuevo los elimina (spec en REPORT.md).
```

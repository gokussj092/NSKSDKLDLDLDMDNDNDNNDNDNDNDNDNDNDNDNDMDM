# REPRODUCE — MinaProNet 88.0.0 (versionCode 88)

Entorno: Python 3.12.3 del sistema, solo stdlib. Sin red, sin secretos.
Todos los comandos se ejecutan desde la raiz del repo (`~/workspace/spdecode-patch`).

## 1. Verificador sanitizado (sin red)

```sh
python3 analysis/vpn.minapronet.com.eg/88/tools/verify.py
```

## 2. Tests del metodo (sin red; `unittest`, stdlib)

```sh
python3 analysis/vpn.minapronet.com.eg/88/tests/test_method.py
python3 analysis/vpn.minapronet.com.eg/88/tests/test_public_servers.py
python3 -m unittest discover -s analysis/vpn.minapronet.com.eg/88/tests -v
```

Si pytest esta instalado, tambien vale:

```sh
python3 -m pytest analysis/vpn.minapronet.com.eg/88/tests/test_method.py -v
```

(En este entorno pytest NO esta instalado en el Python del sistema; `unittest` es la via verificada.)

## 3. Scripts operativos (fuera de este expediente; la clave de formato vive solo ahi)

```sh
python3 ~/workspace/catalogs/minapronet/*.py --self-test
python3 ~/workspace/catalogs/minapronet/*_archivos.py --self-test
```

Self-tests registrados: Catalogo 21/21, archivos 12/12 (scripts operativos, 2026-11-17;
`all_ok` incluido: 22 y 13 líneas OK respectivamente).

La descarga en vivo (`--url`) y la apertura de archivos reales (`--file`) se hacen con esos
scripts operativos; este expediente no reproduce endpoints de descarga ni credenciales.

## 4. Scripts de investigacion en tools/

- `tools/verify.py` — verificador sintetico autocontenido (este expediente).
- `tools/emu_geturl.py` — emulacion Unicorn de `nativeGetConfigUrl` en `libminacore.so` (requiere el .so extraido y Unicorn; rutas absolutas originales documentadas en el script).

## 5. Salida esperada

- `tools/verify.py`: `All N synthetic checks passed (TEST-ONLY keys, no network).`, exit 0.
- `tests/test_method.py`: `Ran N tests ... OK`, exit 0.
- `tests/test_public_servers.py`: `Ran 5 tests ... OK`, exit 0.

## 6. Actualización 2026-11-17 — servidores públicos en vivo

Re-corrida en vivo (requiere red; reproduce `live.json`):

```sh
python3 ~/workspace/catalogs/minapronet/MinaProNet.py --public-servers --json
# Servidores publicos (v2ray-verified.json): 205 entradas, 205 online, 31 paises
# Protocolos: {'ss': 153, 'trojan': 29, 'vless': 17, 'vmess': 6}
```

Comparación contra la referencia (lista de servidores y resumen idénticos):

```sh
python3 - <<'EOF'
import json
fresh = json.loads(open('/tmp/mina_fresh.json').read())  # salida --public-servers --json
live = json.load(open('/home/hatch/workspace/catalogs/minapronet/live.json'))
assert fresh['servers'] == live['servers']
assert {k: fresh[k] for k in ('entries', 'online', 'countries', 'protocols')} == live['summary']
print('live.json reproducido')
EOF
```

Adaptador del worker (sin red; usa el cuerpo crudo descargado con el método de la app):

```sh
python3 - <<'EOF'
import importlib.util
spec = importlib.util.spec_from_file_location('m', 'decoders/Python/apps/MinaProNet/MinaProNet.py')
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
raw = open('/tmp/mina_raw_20261117.bin', 'rb').read()  # cuerpo crudo en vivo, 137266 B
res = m.decode_public_servers(raw)
assert res['entries'] == 205 and res['online'] == 205 and res['countries'] == 31
assert 'url' not in res and 'bytes' not in res
print('decode_public_servers OK')
EOF
```

MinaConfig sigue sin datos (verificación negativa, en vivo):

```sh
python3 ~/workspace/catalogs/minapronet/MinaProNet.py --url https://raw.githubusercontent.com/MinaDiNabil/update.link/refs/heads/main/minapronet.updater
# UPDATER: HTTP_404 ...
```

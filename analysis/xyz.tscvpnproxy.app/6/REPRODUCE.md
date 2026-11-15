# REPRODUCE — TSC VPN Proxy 6.4.3 (versionCode 6)

Entorno: Python 3.12.3 del sistema, solo stdlib. Sin red, sin secretos.
Todos los comandos se ejecutan desde la raiz del repo (`~/workspace/spdecode-patch`).

## 1. Verificador sanitizado (sin red)

```sh
python3 analysis/xyz.tscvpnproxy.app/6/tools/verify.py
```

## 2. Tests del metodo (sin red; `unittest`, stdlib)

```sh
python3 analysis/xyz.tscvpnproxy.app/6/tests/test_method.py
python3 -m unittest discover -s analysis/xyz.tscvpnproxy.app/6/tests -v
```

Si pytest esta instalado, tambien vale:

```sh
python3 -m pytest analysis/xyz.tscvpnproxy.app/6/tests/test_method.py -v
```

(En este entorno pytest NO esta instalado en el Python del sistema; `unittest` es la via verificada.)

## 3. Scripts operativos (fuera de este expediente; la clave de formato vive solo ahi)

```sh
python3 ~/workspace/catalogs/tscvpn/*.py --self-test
python3 ~/workspace/catalogs/tscvpn/*_archivos.py --self-test
```

Self-tests registrados: Catalogo 10/10, archivos 8/8 (scripts operativos, 2026-11-14; re-verificado por coordinador).

La descarga en vivo (`--url`) y la apertura de archivos reales (`--file`) se hacen con esos
scripts operativos; este expediente no reproduce endpoints de descarga ni credenciales.

## 4. Scripts de investigacion en tools/

- `tools/verify.py` — verificador sintetico autocontenido (este expediente).
- `tools/plt_map.json` — mapa PLT de `libisvcrypto.so` (offsets, sin secretos). Los scripts `probe_isv.py` / `live_fetch.py` de `work/` NO se copian: `live_fetch.py` incrusta el endpoint de descarga y `probe_isv.py` depende del archivo de clave de formato; se referencian en el README de la app.

## 5. Salida esperada

- `tools/verify.py`: `All N synthetic checks passed (TEST-ONLY keys, no network).`, exit 0.
- `tests/test_method.py`: `Ran N tests ... OK`, exit 0.

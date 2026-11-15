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

Self-tests registrados: Catalogo 16/16 (8 viejas + 8 nuevas del sitio), archivos 7/7 (scripts operativos, 2026-11-15).

La descarga en vivo (`--url`) y la apertura de archivos reales (`--file`) se hacen con esos
scripts operativos; este expediente no reproduce endpoints de descarga ni credenciales.

## 4. Scripts de investigacion en tools/

- `tools/verify.py` — verificador sintetico autocontenido (este expediente).
- `tools/emu_geturl.py` — emulacion Unicorn de `nativeGetConfigUrl` en `libminacore.so` (requiere el .so extraido y Unicorn; rutas absolutas originales documentadas en el script).

## 5. Salida esperada

- `tools/verify.py`: `All N synthetic checks passed (TEST-ONLY keys, no network).`, exit 0.
- `tests/test_method.py`: `Ran N tests ... OK`, exit 0.

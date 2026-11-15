# REPRODUCE — UT Loop Pro VPN 23.11.26 (versionCode 66)

Entorno: Python 3.12.3 del sistema, solo stdlib. Sin red, sin secretos.
Todos los comandos se ejecutan desde la raiz del repo (`~/workspace/spdecode-patch`).

## 1. Verificador sanitizado (sin red)

```sh
python3 analysis/loop.uchetechs.vpn.pro/66/tools/verify.py
```

## 2. Tests del metodo (sin red; `unittest`, stdlib)

```sh
python3 analysis/loop.uchetechs.vpn.pro/66/tests/test_method.py
python3 -m unittest discover -s analysis/loop.uchetechs.vpn.pro/66/tests -v
```

Si pytest esta instalado, tambien vale:

```sh
python3 -m pytest analysis/loop.uchetechs.vpn.pro/66/tests/test_method.py -v
```

(En este entorno pytest NO esta instalado en el Python del sistema; `unittest` es la via verificada.)

## 3. Scripts operativos (fuera de este expediente; la clave de formato vive solo ahi)

```sh
python3 ~/workspace/catalogs/utloop/*.py --self-test
python3 ~/workspace/catalogs/utloop/*_archivos.py --self-test
```

Self-tests registrados: Catalogo 13/13, archivos 7/7 (scripts operativos, 2026-11-14).

La descarga en vivo (`--url`) y la apertura de archivos reales (`--file`) se hacen con esos
scripts operativos; este expediente no reproduce endpoints de descarga ni credenciales.

## 4. Scripts de investigacion en tools/

- `tools/verify.py` — verificador sintetico autocontenido (este expediente).
- `tools/stringfog.py` — decodificador StringFog generico (XOR `stringfog` + Base64); uso: `stringfog.py <archivo.java>...`.

## 5. Salida esperada

- `tools/verify.py`: `All N synthetic checks passed (TEST-ONLY keys, no network).`, exit 0.
- `tests/test_method.py`: `Ran N tests ... OK`, exit 0.

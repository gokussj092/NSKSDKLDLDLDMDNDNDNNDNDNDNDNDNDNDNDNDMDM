# REPRODUCE — TCx Tunnel Plus 1.0.15 (versionCode 115)

Entorno: Python 3.12.3 del sistema, solo stdlib. Sin red, sin secretos.
Todos los comandos se ejecutan desde la raiz del repo (`~/workspace/spdecode-patch`).

## 1. Verificador sanitizado (sin red)

```sh
python3 analysis/org.tcx.tunnel.plus/115/tools/verify.py
```

## 2. Tests del metodo (sin red; `unittest`, stdlib)

```sh
python3 analysis/org.tcx.tunnel.plus/115/tests/test_method.py
python3 -m unittest discover -s analysis/org.tcx.tunnel.plus/115/tests -v
```

Si pytest esta instalado, tambien vale:

```sh
python3 -m pytest analysis/org.tcx.tunnel.plus/115/tests/test_method.py -v
```

(En este entorno pytest NO esta instalado en el Python del sistema; `unittest` es la via verificada.)

## 3. Scripts operativos (fuera de este expediente; la clave de formato vive solo ahi)

```sh
python3 ~/workspace/catalogs/tcx/*.py --self-test
python3 ~/workspace/catalogs/tcx/*_archivos.py --self-test
```

Self-tests registrados: Ambos scripts --self-test OK (conteos no registrados en NOTES.md).

La descarga en vivo (`--url`) y la apertura de archivos reales (`--file`) se hacen con esos
scripts operativos; este expediente no reproduce endpoints de descarga ni credenciales.

## 4. Scripts de investigacion en tools/

- `tools/verify.py` — verificador sintetico autocontenido (este expediente).
- `tools/resolve_jn.py` — deofuscador LSParanoid (`jn.a(J)`); uso: `resolve_jn.py <jn.java> <apk> <out.txt>` (requiere paranoid-deobfuscator 3.0.2 + androguard).

## 5. Salida esperada

- `tools/verify.py`: `All N synthetic checks passed (TEST-ONLY keys, no network).`, exit 0.
- `tests/test_method.py`: `Ran N tests ... OK`, exit 0.

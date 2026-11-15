# REPRODUCE — Royal Tunnel VPN 7.0 (versionCode 7)

Entorno: Python 3.12.3 del sistema, solo stdlib. Sin red, sin secretos.
Todos los comandos se ejecutan desde la raiz del repo (`~/workspace/spdecode-patch`).

## 1. Verificador sanitizado (sin red)

```sh
python3 analysis/kd.app.royaltunnelplus/7/tools/verify.py
```

## 2. Tests del metodo (sin red; `unittest`, stdlib)

```sh
python3 analysis/kd.app.royaltunnelplus/7/tests/test_method.py
python3 -m unittest discover -s analysis/kd.app.royaltunnelplus/7/tests -v
```

Si pytest esta instalado, tambien vale:

```sh
python3 -m pytest analysis/kd.app.royaltunnelplus/7/tests/test_method.py -v
```

(En este entorno pytest NO esta instalado en el Python del sistema; `unittest` es la via verificada.)

## 3. Scripts operativos (fuera de este expediente; la clave de formato vive solo ahi)

```sh
python3 ~/workspace/catalogs/royaltunnel/*.py --self-test
python3 ~/workspace/catalogs/royaltunnel/*_archivos.py --self-test
```

Self-tests registrados: Catalogo 15/15, archivos 18/18 (scripts operativos, 2026-11-14).

La descarga en vivo (`--url`) y la apertura de archivos reales (`--file`) se hacen con esos
scripts operativos; este expediente no reproduce endpoints de descarga ni credenciales.

## 4. Scripts de investigacion en tools/

- `tools/verify.py` — verificador sintetico autocontenido (este expediente).
- `tools/resolve_hw0.py` — deofuscador LSParanoid (`Hw0.p(J)`); uso: `resolve_hw0.py <Hw0.java> <apk> <out.txt>` (requiere paranoid-deobfuscator 3.0.2 + androguard).

## 5. Salida esperada

- `tools/verify.py`: `All N synthetic checks passed (TEST-ONLY keys, no network).`, exit 0.
- `tests/test_method.py`: `Ran N tests ... OK`, exit 0.

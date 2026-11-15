# REPRODUCE — PPH GOOD VPN 1.7.2 (versionCode 75)

Entorno: Python 3.12.3 del sistema, solo stdlib. Sin red, sin secretos.
Todos los comandos se ejecutan desde la raiz del repo (`~/workspace/spdecode-patch`).

## 1. Verificador sanitizado (sin red)

```sh
python3 analysis/com.skphvpn.mm/75/tools/verify.py
```

## 2. Tests del metodo (sin red; `unittest`, stdlib)

```sh
python3 analysis/com.skphvpn.mm/75/tests/test_method.py
python3 -m unittest discover -s analysis/com.skphvpn.mm/75/tests -v
```

Si pytest esta instalado, tambien vale:

```sh
python3 -m pytest analysis/com.skphvpn.mm/75/tests/test_method.py -v
```

(En este entorno pytest NO esta instalado en el Python del sistema; `unittest` es la via verificada.)

## 3. Scripts operativos (fuera de este expediente; la clave de formato vive solo ahi)

```sh
python3 ~/workspace/catalogs/pph/*.py --self-test
python3 ~/workspace/catalogs/pph/*_archivos.py --self-test
```

Self-tests registrados: Catalogo 25/25, archivos 17/17 tras la limpieza 2026-11-15 (antes 10/10 y 14 checks).

La descarga en vivo (`--url`) y la apertura de archivos reales (`--file`) se hacen con esos
scripts operativos; este expediente no reproduce endpoints de descarga ni credenciales.

## 4. Scripts de investigacion en tools/

- `tools/verify.py` — verificador sintetico autocontenido (este expediente).
- `tools/defog.py` de `work/` NO se copia: incrusta pares de constantes StringFog de la app. El metodo StringFog (XOR + Base64) esta documentado en el README de la app y en ANALYSIS.md.

## 5. Salida esperada

- `tools/verify.py`: `All N synthetic checks passed (TEST-ONLY keys, no network).`, exit 0.
- `tests/test_method.py`: `Ran N tests ... OK`, exit 0.

# tools/ — scripts de investigacion

Scripts propios usados durante la investigacion, sin claves, sin
tokens y sin endpoints. Las constantes de formato viven SOLO en los
scripts operativos de `~/workspace/catalogs/vlx/` (ver MANIFEST.json) y NO se copian aqui.

- `crypto_pure.py`
- `dis_vlx.py`
- `parse_pclntab.py`

`crypto_pure.py` / `aesgcm_pure.py`: criptografia generica extraida
del script operativo (solo funciones, sin constantes de formato).
Los demas son scripts de investigacion tal cual se usaron; algunos
llevan rutas del entorno de origen en su codigo y hay que adaptar la
ruta de entrada al ejecutarlos.

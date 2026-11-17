# Click Tunnel 1.0 — DEPENDENCIES

Inventario legible de herramientas y librerías REALMENTE usadas en esta
investigación. Versiones desconocidas: UNKNOWN con motivo; nunca inventadas.

| Herramienta | Versión | Ecosistema / origen | Propósito | Red |
|---|---|---|---|---|
| Python | 3.12.3 | sistema (verificado) | Ejecución de scripts y tests | No (tests) / Sí (descarga en vivo) |
| pycryptodome | 4.4.0 | PyPI, venv `~/workspace/http-custom-update/venv` (verificado) | AES (CFB/CBC/GCM) de los scripts | No |
| jadx | 1.5.3 | según README de origen | Descompilación DEX a Java | No |
| apktool / androguard | UNKNOWN | UNKNOWN — versión no registrada en los logs de origen | Extracción de APK y lectura de manifest/assets | No |

Herramientas propias: los scripts operativos de
`~/workspace/catalogs/clicktunnel/` (ver MANIFEST.json) y los de
`work/` en ese directorio (`cp0.py` — puerto verificado del
descifrador de cadenas —, `xxtea_test.py`, `fields_test.py`,
`live_response.txt`, `live_outer.json`, decompilación jadx).
No se copian al expediente: referencian respuestas vivas y material
del APK.

**Dependencias de runtime de los scripts entregados: stdlib +
pycryptodome** (`Crypto.Cipher.AES`, `Crypto.Random.get_random_bytes`
en el lector de archivos). pycryptodome está en el `requirements.txt`
raíz del repo (`pycryptodome==3.23.0`), así que la imagen del worker
lo tiene; el venv local tiene 4.4.0. `requests` NO se usa en ningún
script de Click Tunnel (usan `urllib`).

La instalación automática sigue DESHABILITADA según la política. El
lockfile es `dependencies.lock.json` (este expediente).

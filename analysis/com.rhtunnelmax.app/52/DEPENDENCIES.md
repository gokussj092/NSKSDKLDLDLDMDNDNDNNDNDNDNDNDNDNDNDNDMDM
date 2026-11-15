# RH Tunnel Lite 39.0.1 — DEPENDENCIES

Inventario legible de herramientas y librerias REALMENTE usadas en esta
investigacion. Versiones desconocidas: UNKNOWN con motivo; nunca inventadas.

| Herramienta | Version | Ecosistema / origen | Proposito | Red |
|---|---|---|---|---|
| Python | 3.12.3 | sistema (verificado) | Ejecucion de scripts y tests | No (tests) / Si (descarga en vivo) |
| pycryptodome | 4.4.0 | PyPI, venv ~/workspace/http-custom-update/venv (verificado) | Via rapida AES (opcional; hay fallback puro) | No |
| argon2-cffi | 25.1.0 | PyPI, mismo venv (verificado) | Via rapida Argon2id para sobres de campo (opcional) | No |
| jadx | UNKNOWN | UNKNOWN — version no registrada en los logs de origen | Descompilacion DEX a Java | No |
| apktool / androguard | UNKNOWN | UNKNOWN — version no registrada en los logs de origen | Extraccion de APK, manifest y assets | No |
| capstone | UNKNOWN | UNKNOWN — version no registrada en los logs de origen | Desensamblado AArch64 de libgojni.so | No |
| curl | UNKNOWN | sistema — version no registrada | Descarga alternativa si el cliente Python trunca | Si |

Herramientas propias: los scripts operativos de
`~/workspace/catalogs/rhtunnel/` (ver MANIFEST.json) y los de
`tools/` en este expediente. Herramientas de terceros: jadx, apktool,
androguard, capstone (binarios NO copiados al repo; solo nombre, uso y
receta). Herramienta compartida: ninguna de `scripts/apk_analysis/` fue
modificada para estas 7 apps.

La instalacion automatica sigue DESHABILITADA segun la politica. El
lockfile es `dependencies.lock.json` (este expediente).

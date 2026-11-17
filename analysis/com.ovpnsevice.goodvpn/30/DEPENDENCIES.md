# GOOD VPN 3.0 — DEPENDENCIES

Inventario legible de herramientas y librerías REALMENTE usadas en esta
investigación. Versiones desconocidas: UNKNOWN con motivo; nunca
inventadas.

| Herramienta | Versión | Ecosistema / origen | Propósito | Red |
|---|---|---|---|---|
| Python | 3.12.3 | sistema (verificado) | Ejecución de scripts y tests | No (tests) / Sí (descarga en vivo) |
| jadx | 1.5.3 | verificado en los logs de origen | Descompilación DEX a Java | No |
| apktool / androguard | UNKNOWN | UNKNOWN — versión no registrada en los logs de origen | Extracción de APK, manifest y assets | No |
| curl | UNKNOWN | sistema — versión no registrada | Descarga alternativa | Sí |

Los scripts operativos usan **solo la biblioteca estándar de Python**
(`argparse`, `base64`, `binascii`, `http.client`, `json`, `math`, `os`,
`pathlib`, `re`, `struct`, `sys`, `urllib`): ninguna dependencia
externa. La imagen del worker ya trae `requests`
(`requirements.txt`: `requests==2.33.1`) y `argon2-cffi`, pero estos
scripts no los necesitan.

Herramientas propias: los scripts operativos de
`~/workspace/catalogs/goodvpn/` (ver MANIFEST.json) y los de `tools/` en
este expediente. Herramientas de terceros: jadx, apktool, androguard
(binarios NO copiados al repo; solo nombre, uso y receta).

La instalación automática sigue DESHABILITADA según la política. El
lockfile es `dependencies.lock.json` (este expediente).

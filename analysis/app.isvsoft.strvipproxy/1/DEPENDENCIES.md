# STR VIP Proxy 1.42.5 — DEPENDENCIES

Inventario legible de herramientas y librerías REALMENTE usadas en esta
investigación. Versiones desconocidas: UNKNOWN con motivo; nunca inventadas.

| Herramienta | Versión | Ecosistema / origen | Propósito | Red |
|---|---|---|---|---|
| Python | 3.12.3 | sistema (verificado) | Ejecución de scripts y tests | No (tests) / Sí (descarga en vivo) |
| curl | sistema | sistema (verificado: `/usr/bin/curl` existe en este entorno) | Fallback de transporte `--http2` del CLI | Sí |
| Unicorn | UNKNOWN | UNKNOWN — versión no registrada en los logs de origen | Emulación de libisvcrypto.so (firma + AES-GCM) | No |
| jadx | UNKNOWN | UNKNOWN — versión no registrada en los logs de origen | Descompilación DEX a Java | No |
| apktool / androguard | UNKNOWN | UNKNOWN — versión no registrada en los logs de origen | Extracción de APK y lectura de manifest/assets | No |

Herramientas propias: los scripts operativos de
`~/workspace/catalogs/strvipproxy/` (ver MANIFEST.json) y los de
`work/` en ese directorio (no copiados al expediente: referencian
respuestas vivas y material del APK). Herramientas de terceros: jadx,
apktool, androguard, Unicorn (binarios NO copiados al repo; solo
nombre, uso y receta).

**Dependencias de runtime de los scripts entregados: solo stdlib.**
`STR_VIP_Proxy.py` y `STR_VIP_Proxy_archivos.py` importan únicamente
módulos de la biblioteca estándar (`argparse`, `base64`, `gzip`,
`hashlib`, `hmac`, `json`, `subprocess` — solo para el fallback curl
del CLI —, `urllib`, `uuid`, `zipfile`, etc.). No usan `requests`.
Ninguna dependencia nueva para la imagen del worker, salvo notar que
el fallback curl NO existe en ella (Dockerfile sin curl).

La instalación automática sigue DESHABILITADA según la política. El
lockfile es `dependencies.lock.json` (este expediente).

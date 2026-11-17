# Fx Tunnel 4.8 — DEPENDENCIES

Inventario legible de herramientas y librerías REALMENTE usadas en
esta investigación. Versiones desconocidas: UNKNOWN con motivo; nunca
inventadas.

| Herramienta | Version | Ecosistema / origen | Proposito | Red |
|---|---|---|---|---|
| Python | 3.12.3 | sistema (verificado) | Ejecucion de scripts y tests | No |
| jadx | 1.5.3 | UNKNOWN — version segun README de origen (sin registro de procedencia) | Descompilacion DEX a Java (55 errores; OpenVPNClient ausente) | No |
| capstone | UNKNOWN | UNKNOWN — version no registrada en los logs de origen | Desensamblado AArch64 de libputils.so | No |
| apktool / androguard | UNKNOWN | UNKNOWN — version no registrada en los logs de origen | Extraccion de APK, manifest y assets | No |
| curl | UNKNOWN | sistema — version no registrada | Descarga alternativa si el cliente HTTP de Python trunca el cuerpo | Si |

Herramientas propias: los scripts operativos de
`~/workspace/catalogs/fxtunnel/` (ver MANIFEST.json) y `tools/xxtea_pure.py`
de este expediente (XXTEA genérico con clave de prueba, sin claves de
formato). Herramientas de terceros: jadx, capstone, apktool/androguard
(binarios NO copiados al repo; solo nombre, uso y receta). Herramienta
compartida: ninguna de `scripts/apk_analysis/` fue modificada para
esta app.

La instalación automática sigue DESHABILITADA según la política. El
lockfile es `dependencies.lock.json` (este expediente).

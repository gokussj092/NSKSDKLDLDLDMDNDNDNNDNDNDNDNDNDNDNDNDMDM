# ALTAUFIK VPN 5.01 — DEPENDENCIES

Inventario legible de herramientas y librerías REALMENTE usadas en
esta investigación. Versiones desconocidas: UNKNOWN con motivo; nunca
inventadas.

| Herramienta | Version | Ecosistema / origen | Proposito | Red |
|---|---|---|---|---|
| Python | 3.12.3 | sistema (verificado) | Ejecucion de scripts y tests | No (tests) / Si (descarga en vivo) |
| pycryptodome | 4.4.0 | PyPI, venv ~/workspace/http-custom-update/venv (verificado) | AES-256-CBC del script operativo (requerida; el worker de nube fija pycryptodome==3.23.0, misma API) | No |
| androguard | UNKNOWN | UNKNOWN — version no registrada en los logs de origen | Desensamblado dirigido del DEX | No |
| curl | UNKNOWN | sistema — version no registrada | Descarga alternativa si el cliente HTTP de Python trunca el cuerpo | Si |

Herramientas propias: el script operativo de
`~/workspace/catalogs/altaufikvpn/` (ver MANIFEST.json). Herramientas
de terceros: androguard (binario NO copiado al repo; solo nombre, uso
y receta). Herramienta compartida: ninguna de `scripts/apk_analysis/`
fue modificada para esta app.

La instalación automática sigue DESHABILITADA según la política. El
lockfile es `dependencies.lock.json` (este expediente).

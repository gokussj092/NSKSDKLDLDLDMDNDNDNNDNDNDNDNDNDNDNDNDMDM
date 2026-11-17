# M Light 3.1.55 — DEPENDENCIES

Inventario legible de herramientas y librerías REALMENTE usadas en
esta investigación. Versiones desconocidas: UNKNOWN con motivo; nunca
inventadas.

| Herramienta | Versión | Ecosistema / origen | Propósito | Red |
|---|---|---|---|---|
| Python | 3.12.3 | sistema (verificado) | Ejecución de scripts y tests | No (tests) / Sí (descarga en vivo) |
| pycryptodome | 4.5.0 | PyPI, venv de verificación /tmp/dtvenv (verificado 2026-11-17) | Vía rápida AES (opcional; hay fallback puro) | No |
| androguard | UNKNOWN | UNKNOWN — versión no registrada en las notas de origen | Extracción de APK, manifest y assets | No |
| jadx | UNKNOWN | UNKNOWN — versión no registrada en las notas de origen | Descompilación DEX a Java | No |
| curl | UNKNOWN | sistema — versión no registrada | Descarga alternativa / verificación de espejos | Sí |

Herramientas propias: los scripts operativos de
`decoders/Python/apps/M_Light/` (ver MANIFEST.json) y los de
`tools/` en este expediente. Herramientas de terceros: jadx,
androguard, curl (binarios NO copiados al repo; solo nombre, uso y
receta).

La instalación automática sigue DESHABILITADA según la política. El
lockfile es `dependencies.lock.json` (este expediente).

# DeepTune-VPN v8 — DEPENDENCIES

Inventario legible de herramientas y librerías REALMENTE usadas en
esta investigación. Versiones desconocidas: UNKNOWN con motivo; nunca
inventadas.

| Herramienta | Versión | Ecosistema / origen | Propósito | Red |
|---|---|---|---|---|
| Python | 3.12.3 | sistema (verificado) | Ejecución de scripts y tests | No (tests) / Sí (descarga en vivo) |
| argon2-cffi | 25.1.0 | PyPI, venv de verificación /tmp/dtvenv (verificado 2026-11-17) | Argon2id | No |
| cryptography | 50.0.2 | PyPI, venv de verificación /tmp/dtvenv (verificado 2026-11-17) | AES-256-GCM (AESGCM) | No |
| requests | 2.34.2 | PyPI, venv de verificación /tmp/dtvenv (verificado 2026-11-17) | Descarga del catálogo en vivo | Sí |
| pycryptodome | 4.5.0 | PyPI, venv de verificación /tmp/dtvenv (verificado 2026-11-17) | Solo tests del expediente (no la usan los scripts operativos) | No |
| androguard | 4.1.4 | PyPI, venv /tmp/agvenv (verificado 2026-11-17) | Lectura de package/versionCode/versionName del base.apk | No |
| jadx | UNKNOWN | UNKNOWN — versión no registrada en el trabajo previo (existe `work/jadx/` en el análisis original) | Descompilación DEX a Java | No |

Herramientas propias: los scripts operativos de
`decoders/Python/apps/DeepTune_VPN/` (ver MANIFEST.json) y los de
`tools/` en este expediente. Herramientas de terceros: jadx,
androguard (binarios NO copiados al repo; solo nombre, uso y receta).

La instalación automática sigue DESHABILITADA según la política. El
lockfile es `dependencies.lock.json` (este expediente).

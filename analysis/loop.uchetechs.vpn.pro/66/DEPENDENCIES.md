# DEPENDENCIES — UT Loop Pro VPN 23.11.26 (versionCode 66)

Inventario de herramientas y librerias REALMENTE usadas en esta investigacion.
Versiones marcadas UNKNOWN no se registraron en NOTES.md ni en el README de la app: no se inventan.
Los scripts operativos son Python 3 stdlib puro (sin dependencias PyPI en runtime).

| Herramienta / libreria | Version | Ecosistema | Proposito | Red |
|---|---|---|---|---|
| Python | 3.12.3 (system) | sistema | stdlib only in operational scripts | no (local) |
| jadx | UNKNOWN (version not recorded; died at 58%) | sistema | partial decompilation; all com/utloop decompiled | si (descarga) / no (uso) |
| androguard | UNKNOWN (version not recorded) | PyPI | DEX inspection (androguard.db/log in work/) | si (descarga) / no (uso) |

## Notas
- pytest NO esta instalado en el Python del sistema de este entorno (Python 3.12.3): los tests de este expediente usan `unittest` (stdlib) y son compatibles en forma con pytest cuando este instalado.
- Unicorn y PyCryptodome se usaron SOLO como oraculo de verificacion durante la investigacion; los scripts operativos no los necesitan.
- `tools/verify.py` y `tests/test_method.py` son stdlib puro y no necesitan instalacion.

## Lockfile
Ver `dependencies.lock.json`. Las entradas UNKNOWN llevan estado NEEDS_REVIEW.

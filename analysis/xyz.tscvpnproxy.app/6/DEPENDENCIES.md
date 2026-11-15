# DEPENDENCIES — TSC VPN Proxy 6.4.3 (versionCode 6)

Inventario de herramientas y librerias REALMENTE usadas en esta investigacion.
Versiones marcadas UNKNOWN no se registraron en NOTES.md ni en el README de la app: no se inventan.
Los scripts operativos son Python 3 stdlib puro (sin dependencias PyPI en runtime).

| Herramienta / libreria | Version | Ecosistema | Proposito | Red |
|---|---|---|---|---|
| Python | 3.12.3 (system) | sistema | stdlib only in operational scripts | no (local) |
| Unicorn | UNKNOWN (version not recorded in NOTES.md) | binario oficial / PyPI | emulation oracle of libisvcrypto.so nativeDecrypt/nativeEncrypt/nativeSignProof | si (descarga) / no (uso) |
| PyCryptodome | UNKNOWN (version not recorded) | binario oficial / PyPI | oracle for cross-checking the pure-Python AES-GCM; NOT used by the operational scripts | si (descarga) / no (uso) |

## Notas
- pytest NO esta instalado en el Python del sistema de este entorno (Python 3.12.3): los tests de este expediente usan `unittest` (stdlib) y son compatibles en forma con pytest cuando este instalado.
- Unicorn y PyCryptodome se usaron SOLO como oraculo de verificacion durante la investigacion; los scripts operativos no los necesitan.
- `tools/verify.py` y `tests/test_method.py` son stdlib puro y no necesitan instalacion.

## Lockfile
Ver `dependencies.lock.json`. Las entradas UNKNOWN llevan estado NEEDS_REVIEW.

# DEPENDENCIES — ANY VPN build 40 (versionCode 40)

Inventario de herramientas y librerías REALMENTE usadas en esta investigación.
Versiones marcadas UNKNOWN no se registraron en los logs de origen: no se inventan.

| Herramienta / librería | Versión | Ecosistema | Propósito | Red |
|---|---|---|---|---|
| Python | 3.12.3 (system) | sistema | Ejecución de scripts y tests | No (tests) / Sí (descarga en vivo) |
| pycryptodome | 3.23.0 | PyPI | AES-256-CBC del codec (runtime del worker y tests) | No |
| requests | 2.33.1 | PyPI | Descarga en vivo en el script de investigación ANY_VPN.py (el codec del repo usa urllib stdlib) | Sí |
| jadx | UNKNOWN | UNKNOWN — versión no registrada en los logs de origen | Descompilación DEX a Java | No |

Herramientas propias: el script de investigación `~/workspace/catalogs/anyvpn/ANY_VPN.py`,
`ANY_VPN_archivos.py` y `tools/deobfuscate.py` (este expediente). Herramientas de terceros:
jadx (binario NO copiado al repo; solo nombre, uso y receta).

## Lockfile

Ver `dependencies.lock.json`. Las entradas UNKNOWN llevan estado NEEDS_REVIEW.

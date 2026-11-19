# V2Box 6.2.3 (build 88) — DEPENDENCIES

Inventario real de lo usado en la investigación/corrección del AAD
v2 (2026-11-19). Sin instalaciones nuevas; sin dependencias nuevas
en producción.

## Producción (decodificador operativo)

| Nombre | Versión | Ecosistema | Propósito | Licencia / origen |
| --- | --- | --- | --- | --- |
| Python | 3.12.3 | sistema (Ubuntu) | runtime del decodificador y del worker | PSF |
| Biblioteca estándar de Python (`hashlib`, `hmac`, `json`, `base64`, `struct`, `unicodedata`) | 3.12.3 | stdlib | AES-256-GCM, ECDH P-256 y HKDF implementados en `V2Box_archivos.py` | PSF |

`decoders/Python/apps/V2Box/V2Box_archivos.py` es stdlib puro: no
añade dependencias de producción.

## Tests (no producción)

| Nombre | Versión | Ecosistema | Propósito | Licencia / origen |
| --- | --- | --- | --- | --- |
| PyCryptodome (`Crypto`) | 4.5.0 | PyPI | Oráculo independiente AES-GCM en `tests/test_v2box_password.py` y en el self-test del decodificador (verificación cruzada, opcional) | BSD / Apache-2.0 |
| `unittest` | 3.12.3 | stdlib | `tests/test_v2box_aad.py`, `tests/test_v2box_password.py` | PSF |

## Herramientas de terceros (análisis estático, sin redistribuir)

| Nombre | Versión | Propósito |
| --- | --- | --- |
| `strings` (binutils) | sistema | búsqueda de cadenas en `classes.dex` |
| JADX (salida previa en `~/workspace/catalogs/v2box/work/jadx-out/`) | UNKNOWN (salida heredada del expediente 88, fuera de Git) | descompilado del APK 6.2.3/88 para localizar el sobre `zg2` y el GCM; la traza estática del AAD no fue concluyente y NO se usó como prueba (la prueba fue el archivo real) |

No se copiaron binarios de terceros ni código con licencia
incompatible al repositorio. No se guardaron APK, claves, ni valores
del archivo real en Git.

## Revisión de conexión (heredado)

Registro detallado: [DEPENDENCIES.md](../../platform/supplied-integrations/2026-11-14/DEPENDENCIES.md).

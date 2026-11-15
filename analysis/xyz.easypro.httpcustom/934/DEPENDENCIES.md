# Dependencias ejecutadas — build 934

Estado: investigación manual; no se aprueban automáticamente adaptadores F7.

| Componente | Versión | Función | Origen / licencia |
| --- | --- | --- | --- |
| CPython | 3.12.14 | Herramientas y tests | python.org / PSF |
| PyCryptodome | 3.23.0 | XChaCha20-Poly1305 y claves RSA públicas | pycryptodome.org / BSD y dominio público |
| argon2-cffi | 25.1.0 | Derivación con contraseña | argon2-cffi.readthedocs.io / MIT |
| argon2-cffi-bindings | 26.1.0 | Backend Argon2 | PyPI / MIT; revisar licencias transitivas antes de redistribuir |
| CFFI / pycparser | 2.1.1 / 3.12 | Dependencias del backend | PyPI / MIT y BSD |
| Unicorn | 2.1.4 | Emulación ARM64 limitada sin red | unicorn-engine.org / GPLv2 |
| Capstone | 5.0.7 | Inspección AArch64 | capstone-engine.org / BSD |
| pyelftools | 0.32 | Segmentos y relocaciones ELF | github.com/eliben/pyelftools / dominio público |
| JADX | 1.5.3 | Lectura de firmas DEX; 55 errores generales | github.com/skylot/jadx / Apache-2.0 |
| OpenJDK | 21.0.13 | Ejecución de JADX | openjdk.org / GPLv2 con Classpath Exception |

Versiones fijadas y hash de distribución JADX en `dependencies.lock.json`.
Linux x86_64; bibliotecas objeto Android ARM64. No se añaden binarios de
terceros a Git. El emulador compartido está en `scripts/apk_analysis/arm64_function.py`
y su lector ELF en `scripts/apk_analysis/elf_inspect.py`, base `932667d`.
Las recetas previas del checkpoint privado 914 inspiraron el modelo JNI;
no se cargaron sus snapshots pickle ni se ejecutó el ciclo de vida Android.
La caché nueva usa JSON y bytes locales, y queda fuera de Git.

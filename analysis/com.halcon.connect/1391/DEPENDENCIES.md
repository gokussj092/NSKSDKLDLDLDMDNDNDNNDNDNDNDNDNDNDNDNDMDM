# Herramientas y dependencias realmente observadas

Estado: uso manual de investigación. **UNREVIEWED para autoejecución Fase7**.
No hay registro central APPROVED ni validador CI implementados por este trabajo.
Las licencias transitivas requieren revisión; instalar no equivale a aprobar.

## Entorno y herramientas

| Herramienta | Versión real | Origen / licencia | Uso y red |
| --- | --- | --- | --- |
| CPython | 3.12.14 | https://www.python.org/ ; PSF | Scripts/unittest/hashlib/base64/urllib/zipfile/json; stdlib sin dependencias pip añadidas |
| OpenJDK | 17.0.20+8-1-24.04-Ubuntu | https://openjdk.org/ ; GPL2+Classpath Exception | Java/JCA en modo fuente; sin red; javac ausente de PATH |
| JADX | 1.5.6 | https://github.com/skylot/jadx/releases/tag/v1.5.6 ; Apache2 | Instalación oficial checksum-pinned; decompilación local;22 errores en DEX1 |
| curl | 8.5.0, parche Ubuntu8.5.0-2ubuntu10.13 | https://curl.se/ ; curl license | GET públicos Play/APKPure/backup; TLS y proxy del entorno conservados |
| rg | versión de ejecutor no fijada/NEEDS_REVIEW | https://github.com/BurntSushi/ripgrep ; MIT/Unlicense | Búsqueda local; no dependencia del método |
| Shell/utilidades de archivos | versión no fijada/NEEDS_REVIEW | Ubuntu/GNU, revisar cada paquete | mkdir/chmod/cp/cmp/readelf/strings para exploración local; no producción |
| lxml del runtime principal | 6.1.1 | https://lxml.de/ ; BSD | Parser de HTML en exploración inicial; distinto del lxml del venv |
| GitHub/Library/Search conectados | versión del servicio no expuesta/UNKNOWN | Servicios conectados | Lectura de política/código y búsqueda de muestra; Library y buscadores sin coincidencia exacta útil |

Curl reportó OpenSSL3.0.13, zlib1.3, brotli1.1.0, zstd1.5.5, libidn2.3.7,
libpsl0.21.2, libssh0.10.6/OpenSSL/zlib, nghttp2.1.59.0, librtmp2.3 y
OpenLDAP2.6.7. Son dependencias del binario de sistema; sus paquetes/hashes y
licencias individuales no se validaron para redistribución/auto ejecución.
Salida exacta conservada en dependencies.lock.json; no se copiaron binarios.

Los archivos compartidos `inspect_apk.py`, `decompile.py`, `elf_inspect.py` y
requirements.txt se usaron sin modificar. Commit de referencia y checksums en
MANIFEST/dependencies.lock. Los scripts propios están en tools/, incluidas
las revisiones fallidas de probe. La interpretación candidata no está en runtime.

## Entorno Python aislado

La tabla diferencia uso directo de dependencias instaladas transitivamente.
Las42 versiones están fijadas en requirements.lock.txt y dependencies.lock.json.
No se capturaron hashes de las distribuciones durante pip install: null y
NEEDS_REVIEW; no inventar hashes. `source` y `license` del lock proceden de la
metadata instalada, no de una auditoría jurídica independiente.

| Paquete | Versión | Propósito / estado |
| --- | --- | --- |
| alembic | 1.20.1 | Transitiva instalada del entorno de análisis; no ejecutada ni validada por separado. |
| androguard | 4.1.4 | Inspección estática del manifiesto y certificado APK; invocado. |
| apkInspector | 1.3.7 | Transitiva instalada del entorno de análisis; no ejecutada ni validada por separado. |
| asn1crypto | 1.5.1 | Transitiva instalada del entorno de análisis; no ejecutada ni validada por separado. |
| asttokens | 3.0.2 | Transitiva instalada del entorno de análisis; no ejecutada ni validada por separado. |
| capstone | 5.0.9 | Desensamblado ARM64 por ElfImage; invocado. |
| cffi | 2.1.1 | Transitiva instalada del entorno de análisis; no ejecutada ni validada por separado. |
| click | 8.5.0 | Transitiva instalada del entorno de análisis; no ejecutada ni validada por separado. |
| colorama | 0.4.6 | Transitiva instalada del entorno de análisis; no ejecutada ni validada por separado. |
| cryptography | 50.0.2 | Transitiva instalada del entorno de análisis; no ejecutada ni validada por separado. |
| dataset | 2.0.0 | Transitiva instalada del entorno de análisis; no ejecutada ni validada por separado. |
| executing | 2.3.0 | Transitiva instalada del entorno de análisis; no ejecutada ni validada por separado. |
| ipython | 9.18.1 | Transitiva instalada del entorno de análisis; no ejecutada ni validada por separado. |
| ipython_pygments_lexers | 1.1.1 | Transitiva instalada del entorno de análisis; no ejecutada ni validada por separado. |
| jedi | 0.20.1 | Transitiva instalada del entorno de análisis; no ejecutada ni validada por separado. |
| loguru | 0.7.3 | Silenciar logs del inspector Androguard; invocado. |
| lxml | 6.1.3 | Transitiva instalada del entorno de análisis; no ejecutada ni validada por separado. |
| Mako | 1.4.3 | Transitiva instalada del entorno de análisis; no ejecutada ni validada por separado. |
| MarkupSafe | 3.0.4 | Transitiva instalada del entorno de análisis; no ejecutada ni validada por separado. |
| matplotlib-inline | 0.2.2 | Transitiva instalada del entorno de análisis; no ejecutada ni validada por separado. |
| mutf8 | 1.1.0 | Transitiva instalada del entorno de análisis; no ejecutada ni validada por separado. |
| networkx | 3.7 | Transitiva instalada del entorno de análisis; no ejecutada ni validada por separado. |
| parso | 0.8.7 | Transitiva instalada del entorno de análisis; no ejecutada ni validada por separado. |
| pexpect | 4.9.0 | Transitiva instalada del entorno de análisis; no ejecutada ni validada por separado. |
| pillow | 13.0.0 | Transitiva instalada del entorno de análisis; no ejecutada ni validada por separado. |
| pip | 25.0.1 | Instalación y listado del entorno; invocado. |
| prompt_toolkit | 3.0.53 | Transitiva instalada del entorno de análisis; no ejecutada ni validada por separado. |
| psutil | 7.2.2 | Transitiva instalada del entorno de análisis; no ejecutada ni validada por separado. |
| ptyprocess | 0.7.0 | Transitiva instalada del entorno de análisis; no ejecutada ni validada por separado. |
| pure_eval | 0.2.4 | Transitiva instalada del entorno de análisis; no ejecutada ni validada por separado. |
| pycparser | 3.12 | Transitiva instalada del entorno de análisis; no ejecutada ni validada por separado. |
| pycryptodome | 3.23.0 | AES256-GCM del candidato y entradas negativas; invocado. |
| pydot | 4.0.1 | Transitiva instalada del entorno de análisis; no ejecutada ni validada por separado. |
| pyelftools | 0.33 | Lectura ELF y mapeo de segmentos; invocado. |
| Pygments | 2.21.0 | Transitiva instalada del entorno de análisis; no ejecutada ni validada por separado. |
| pyparsing | 3.3.3 | Transitiva instalada del entorno de análisis; no ejecutada ni validada por separado. |
| PyYAML | 6.0.3 | Transitiva instalada del entorno de análisis; no ejecutada ni validada por separado. |
| SQLAlchemy | 2.1.6 | Transitiva instalada del entorno de análisis; no ejecutada ni validada por separado. |
| stack-data | 0.6.3 | Transitiva instalada del entorno de análisis; no ejecutada ni validada por separado. |
| traitlets | 5.16.1 | Transitiva instalada del entorno de análisis; no ejecutada ni validada por separado. |
| typing_extensions | 4.16.0 | Transitiva instalada del entorno de análisis; no ejecutada ni validada por separado. |
| wcwidth | 0.9.4 | Transitiva instalada del entorno de análisis; no ejecutada ni validada por separado. |

## Reproducción, aislamiento y límites

Instalación en venv con el lock exacto; adquisición requiere red pública.
Las pruebas sintéticas y la lectura ELF/APK posteriores son offline. No se usa
root, Frida, fuerza bruta, evasión de Play, emulación de identidad válida ni
librería nativa cargada por el sistema. Las recetas y constantes recuperadas
se escriben0600 fuera de Git; los fixtures solo contienen datos sintéticos.

La prueba principal autenticada quedó bloqueada por auto-review y requiere
autorización explícita. No es una incompatibilidad de urllib ni una prueba de
fallo del proveedor. Las herramientas de este expediente NO son adaptadores
aprobados para ejecutar automáticamente sobre APK futuras.

Versiones de utilidades efectivamente disponibles: ripgrep 15.2.0 (rev e89fff89ac); GNU bash, version 5.2.21(1)-release (x86_64-pc-linux-gnu); GNU readelf (GNU Binutils for Ubuntu) 2.42; GNU strings (GNU Binutils for Ubuntu) 2.42; cmp (GNU diffutils) 3.10; git version 2.51.1.

## Herramientas adicionales del cierre autorizado

- Node.js **24.22.1**, https://nodejs.org/, licencia MIT/componentes incluidos: pruebas del broker, contrato y replay real. Solo módulos nativos; no paquetes npm nuevos.
- Pillow **13.0.0** se ejecutó ahora realmente para convertir el launcher WebP original en PNG sin cambiar píxeles; WebP incluido **1.6.0**. Fuente https://chromium.googlesource.com/webm/libwebp; licencia transitiva pendiente de revisión.
- Java/JCA se ejecutó también con los bytes reales del catálogo; igualdad completa con CLI y worker. El material privado se pasa por entorno, nunca argumentos ni stdout.
- recover.py corregido: SHA256(DER) directo; revisión Base64 errónea conservada. probe.py autorizado por el propietario en esta continuación.
- La transferencia privada de entregables usa los helpers actuales de ChatGPT Library; no son dependencia del método ni del worker y no se incorporan al runtime.

# F7-A0-P01 — Auditoría de dependencias, licencia y procedencia

Fecha: 2026-11-06. Rama: feat/nuevas-integraciones. ESTADO: PARCIAL, no aprobación para automatización comercial.

## Alcance y conservación
Los 63 scripts preexistentes corresponden en 63/63 a los Git blob OIDs del inventario baseline. Las herramientas han dado buenos resultados con Work, según el propietario. Esta fase preserva esas herramientas sin editar, reescribir, reinstalar o ejecutar sus métodos. El objetivo es estudiar las bibliotecas que podrían requerir los futuros workers F7-A5.

## Matriz revisada con la publicación oficial
| Dependencia | Versión | Licencia que reporta upstream | Observación |
| --- | --- | --- | --- |
| [Androguard](https://pypi.org/project/androguard/4.1.4/) | 4.1.4 | Apache-2.0; clasificador PyPI Other/Proprietary | 14 Requires-Dist; falta lock transitivo |
| [Pillow](https://pypi.org/project/pillow/13.0.0/) | 13.0.0 | MIT-CMU | Requiere Python >=3.11, README indica 3.10+ |
| [pyelftools](https://pypi.org/project/pyelftools/0.33/) | 0.33 | Public Domain | Wheel/ABI aún sin verificar |
| [Capstone](https://pypi.org/project/capstone/5.0.9/) | 5.0.9 | BSD | Ruedas binarias por arquitectura |
| [Unicorn](https://pypi.org/project/unicorn/2.1.4/) | 2.1.4 | Conflicto metadata BSD frente a descripción GPLv2 | Revisar core, bindings y QEMU antes de redistribución |
| [PyCryptodome](https://pypi.org/project/pycryptodome/3.23.0/) | 3.23.0 | BSD / Public Domain | Wheel instalado por ABI pendiente |
| [CairoSVG](https://pypi.org/project/CairoSVG/2.9.1/) | 2.9.1 | LGPL-3.0-or-later | Cairo nativo y cumplimiento pendientes |

Para cada versión se transcribió un **SHA-256 de distribución fuente SDIST** publicado en PyPI con el nombre de archivo exacto. Este checksum NO representa una rueda instalada de Linux ni un lock de todas las transitivas. El campo distribution_sha256 sigue null para no inventar una instalación.

## Complementos ya usados por el proyecto
- [JADX v1.5.6](https://github.com/skylot/jadx/releases/tag/v1.5.6): [licencia Apache-2.0](https://github.com/skylot/jadx/blob/v1.5.6/LICENSE). En decompile.py existen y se comprueban en su flujo normal los SHA-256 ZIP 545ea2be9c242511bc145755cf4bda2485ade42966e096f8b4d3da2a230e8974 y JAR fe3e12c45acf75f92369685fd02d1d7a7323385dc725680a9b98a0dac0ea554b. No se descargó el artefacto en esta auditoría.
- JDK 17+, paquete y licencia dependientes de distribución.
- Frida 17.24.3 y frida-tools 14.11.0: referencias de ha_runtime_capture.py fuera del requirements.txt. La instrumentación requiere autorización y sandbox individual.
- libsodium/Cairo nativos y ADB/Android SDK/Node: dependencias según método; no asignar versiones globales ficticias.

## Pendientes que impiden cerrar P01
1. Inspección del wheel instalado por plataforma (Linux x86_64/ARM64), SHA-256 de ese artefacto, lock transitivo reproducible y verificación de dependencias nativas.
2. Determinar Python efectivo >=3.11 para instalar el conjunto completo actual, sin cambiar ni degradar bibliotecas probadas por Work.
3. Resolver la información de licencia Unicorn, obligaciones LGPL y licencias específicas de compilaciones nativas y Frida.
4. Evidencia del entorno sandbox y permisos para P02/P03, sin convertir las herramientas existentes en ejecución desatendida por el mero inventario.

## Validación automatizada
El archivo scripts/ci/check_apk_tool_dependencies.py compara requisitos fijos, versiones, fuentes y hashes SDIST; rechaza discrepancias, hashes falsamente rotulados como wheels o habilitación de ejecución. Pruebas offline: tests/test_a0_dependency_inventory.py. El workflow F7-A0 los ejecuta sin descargar, instalar ni abrir APKs. Esta auditoría no pretende probar la funcionalidad del analizador ni cambiar sus métodos.


### Validación CI de P01 (GitHub Actions)

[F7-A0 Method Evidence, run 42314608709](https://github.com/gokussj092/NSKSDKLDLDLDMDNDNDNNDNDNDNDNDNDNDNDNDMDM/actions/runs/42314608709), resultado **SUCCESS** (commit f263c3587e9cca8d9a87496b95cf9ab7880719b9). Ejecutados 11 tests de evidencia + 6 tests nuevos de metadatos. Inventario: 63 scripts, 7 pins directos, 11 dossiers. Verificador P01: 7 SDIST de referencia, 0 wheels instalados atestiguados y 0 autorizaciones automáticas. Estado P01 **PARCIAL**, pendiente wheel/ABI/transitivas/revisión jurídica. No implica fallo funcional de herramientas anteriores.

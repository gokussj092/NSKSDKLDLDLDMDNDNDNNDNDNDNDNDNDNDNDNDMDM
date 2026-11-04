# Herramientas y dependencias ejecutadas

Runtime operativo: biblioteca estándar Python y validadores JSON compartidos de
BD_NET_VPN; Node usa módulos built-in. No AES/XXTEA ni paquetes nuevos para este
catálogo. Se reutiliza el venv de análisis existente; no se instala nada aquí.

| Herramienta | Versión usada | Uso y origen | Licencia / revisión |
| --- | --- | --- | --- |
| CPython | 3.12.14 | JSON, urllib, hashes, CLI; python.org | PSF |
| Node.js | 24.22.1 | Broker, tests, JsonOracle; nodejs.org | MIT |
| OpenJDK | 17.0.20+8 | Ejecutar JADX; openjdk.org | GPLv2 + Classpath Exception |
| JADX | 1.5.6 | skylot/jadx release oficial, JAR fijado | Apache-2.0 |
| Androguard | 4.1.4 | Manifiesto, certificado, DEX; github.com/androguard/androguard | Apache-2.0 |
| pyelftools | 0.33 | ELF offline; github.com/eliben/pyelftools | Dominio público |
| Pillow | 13.0.0 | Verificar PNG, sin recodificar; python-pillow.org | MIT-CMU |
| Loguru | 0.7.3 | Silenciar logs de Androguard; github.com/Delgan/loguru | Metadata de distribución UNKNOWN; NEEDS_REVIEW |
| curl | 8.5.0 | Descarga HTTPS a través del proxy heredado; curl.se | curl license |
| ripgrep | 15.2.0 | Buscar código; github.com/BurntSushi/ripgrep | MIT/Unlicense |
| Bash | 5.2.21 | Orquestación local; gnu.org/software/bash | GPLv3+ |

`dependencies.lock.json` contiene el inventario real de42 paquetes instalados,
versiones, Requires-Dist, fuentes y licencias de sus metadatos. No se afirma que
todos fueran importados por el método. Directos: Androguard/pyelftools/Pillow/
Loguru; transitivos según Requires-Dist. Hashes de archivos de distribución null:
no se conservaron al instalar previamente este venv; no se inventan ni se copian
de otro entorno. Preparación reproducible mediante `requirements.lock.txt`.
Capstone/PyCryptodome están instalados; CATNET no los usa directamente.

JADX ZIP SHA256545ea2be9c242511bc145755cf4bda2485ade42966e096f8b4d3da2a230e8974;
JAR SHA256fe3e12c45acf75f92369685fd02d1d7a7323385dc725680a9b98a0dac0ea554b.
Se verificó y reutilizó el JAR, no se redistribuye en Git. Sistema Linux x86_64;
APK ARM64 inspeccionada estáticamente, nunca ejecutada. No NDK/emulador/Blutter.

Herramientas compartidas sin cambios: scripts/apk_analysis/inspect_apk.py,
decompile.py; generador de inventario
analysis/com.halcon.connect/1391/tools/dependency_inventory.py. Scripts propios
en tools/, con hashes en MANIFEST: prepare, scan, dex_trace, source_evidence,
probe, signature, extract_icon, make_fixture, JsonOracle, verify, probe_node,
run_checks y finalize; history conserva intentos anteriores. Se ejecutan manualmente,
sin aprobación para reutilización automática Fase7. Licencias transitivas y
registro central de herramientas siguen NEEDS_REVIEW; no se afirma control CI.

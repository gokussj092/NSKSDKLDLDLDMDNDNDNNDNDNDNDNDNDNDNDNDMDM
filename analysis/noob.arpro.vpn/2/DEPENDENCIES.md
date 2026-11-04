# Dependencias y herramientas reales

Se reutiliza el venv existente, sin instalar paquetes. No existe runtime
operativo nuevo para AR PRO. Los42 paquetes instalados y sus relaciones
Requires-Dist se inventarían en dependencies.lock.json/requirements.lock.txt;
no implica que todos fueran ejecutados. Hashes de distribución null porque no
se conservaron en la instalación previa, sin inventarlos de otro entorno.

| Herramienta | Versión | Uso / origen | Licencia o revisión |
| --- | --- | --- | --- |
| CPython | 3.12.14 | urllib/JSON/hash/orquestación; python.org | PSF |
| OpenJDK | 17.0.20+8 | JADX y StringOracle; openjdk.org | GPLv2 + Classpath Exception |
| JADX | 1.5.6 | Decompilación estática, skylot/jadx release oficial | Apache-2.0 |
| Androguard | 4.1.4 | APK/DEX/recursos; github.com/androguard/androguard | Apache-2.0 |
| pyelftools | 0.33 | ELF/relocations; github.com/eliben/pyelftools | Dominio público |
| Capstone | 5.0.9 | AArch64 offline; capstone-engine.org | Metadata UNKNOWN, NEEDS_REVIEW |
| PyCryptodome | 3.23.0 | Autenticar campos GCM observados; pycryptodome.org | BSD/Public Domain, revisión transitiva pendiente |
| cryptography | 50.0.2 | Abrir XTS incluido con OpenSSL; cryptography.io | Apache-2.0/BSD-3-Clause, revisión transitiva pendiente |
| Pillow | 13.0.0 | Inspector de icono PNG, sin publicar uno nuevo; python-pillow.org | MIT-CMU |
| Loguru | 0.7.3 | Desactivar logs de Androguard; github.com/Delgan/loguru | Metadata UNKNOWN, NEEDS_REVIEW |
| curl | 8.5.0 | Descarga HTTPS por proxy heredado; curl.se | curl license |
| ripgrep | 15.2.0 | Búsqueda de fuentes; BurntSushi/ripgrep | MIT/Unlicense |
| GNU readelf | 2.42 | Símbolos ELF; GNU Binutils | GPLv3+ |
| Bash | 5.2.21 | Comandos locales; gnu.org/software/bash | GPLv3+ |

Linux x86_64; bibliotecas ARM64 inspeccionadas, nunca ejecutadas. Shared tools
sin cambios: scripts/apk_analysis/{inspect_apk.py,decompile.py,elf_inspect.py},
analysis/net.catnet.vpn/27/tools/dex_trace.py y
analysis/com.halcon.connect/1391/tools/dependency_inventory.py. Scripts propios
en tools/: prepare, extract_resources, StringOracle, resolve_strings, probe, recover,
probe_configured_sources, verify_pending, finalize. No Android SDK/Gradle,
NDK, emulador ni ejecución de nativos. No se instalan herramientas nuevas.

JADX JAR fijado SHA256fe3e12c45acf75f92369685fd02d1d7a7323385dc725680a9b98a0dac0ea554b;
ZIP oficial545ea2be9c242511bc145755cf4bda2485ade42966e096f8b4d3da2a230e8974.
No se redistribuye. Todas las herramientas son de investigación manual,
no aprobadas para ejecución automática Fase7. Revisión central de licencias,
registro aprobado y validador CI siguen pendientes.

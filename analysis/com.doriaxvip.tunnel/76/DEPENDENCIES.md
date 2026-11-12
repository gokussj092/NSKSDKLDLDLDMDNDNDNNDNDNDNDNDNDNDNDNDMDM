# Herramientas y dependencias

| Herramienta | Versión usada | Origen / licencia | Uso |
| --- | --- | --- | --- |
| CPython | 3.12.14 | python.org / PSF | Recetas, stdlib, CLI y worker |
| PyCryptodome (`Crypto`) | 3.23.0 | pycryptodome.org / BSD + código público según distribución | AES-CBC, padding y pruebas; operación |
| Androguard | 4.1.4 | github.com/androguard/androguard / Apache-2.0 | Manifest, ARSC, certificados y AXML; análisis |
| Pillow | 13.0.0 | python-pillow.github.io / HPND según distribución | Decodificar el launcher WEBP y guardar PNG sin cambiar píxeles |
| Loguru | 0.7.3 | github.com/Delgan/loguru / metadato local UNKNOWN, revisión pendiente | Silenciar logs de Androguard |
| JADX | 1.5.6 | github.com/skylot/jadx / Apache-2.0 | Decompilación estática del DEX; parcial, exit3/14 errores |
| OpenJDK / JCA | 17.0.20 | openjdk.org / GPL-2.0 con Classpath Exception | JADX y oráculo Java independiente, sin Android |
| Node.js | 24.22.1 | nodejs.org / MIT y componentes de distribución | Broker, gateway y tests; APIs nativas, sin paquetes npm nuevos |
| curl | 8.5.0 | curl.se / curl | Descarga real del XAPK |
| ripgrep / Bash | 15.2.0 / 5.2.21 | github.com/BurntSushi/ripgrep / MIT-Unlicense; gnu.org/software/bash / GPL | Buscar rutinas y ejecutar comandos |
| GitHub y recuperación web | Versión no expuesta | Servicios conectados, términos del servicio | Identificación pública y persistencia Git, sin leer credenciales |

El lock registra los 42 paquetes instalados del venv, sus dependencias declaradas, versiones, fuentes y licencias disponibles. Inventario de instalación no significa que se hayan usado todos. No se instalaron Unicorn, Frida, paquetes nuevos, SDK Android ni software de fuerza bruta. No se utilizó la desensamblación ELF; elf_inspect.py figura en el inventario compartido porque ese inventario lo incluye, no porque se ejecutara aquí.

Scripts propios físicos: prepare, recover, resources, census, set_constants, verify, CatalogOracle.java, make_vectors, integrate, probe_node, run_checks y finalize. Revisiones ejecutadas en tools/history. Hashes en MANIFEST.json. Código compartido canónico: inspect_apk.py, decompile.py, dependency_inventory.py y HTTP_FenixVPN/codec.py con field_names.json; rutas y checksums en el lock. No se modificaron esos recursos compartidos.

JADX ZIP/JAR fijados por hashes oficiales conservados en el wrapper. Hashes de paquetes instalados no retenidos: null con explicación; licencias y registro central necesitan revisión para reutilización automática de la futura fase 7. La investigación manual actual no declara esas herramientas APPROVED para automatización. Datos de APK, constantes de investigación, licencias/assets originales y perfiles reales permanecen privados; solo las constantes del formato implementado se conservan inline en el backend autorizado.

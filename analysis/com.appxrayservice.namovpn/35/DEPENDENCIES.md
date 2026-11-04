# Dependencias y herramientas realmente utilizadas

Linux x86_64, entorno Python aislado nuevo. Runtime NAMO: biblioteca estándar y
validadores canónicos de BD_NET_VPN, sin cambios en ese proveedor. Análisis:
Androguard, pyelftools, Capstone, Pillow y Loguru. PyCryptodome se instaló como
parte del entorno de worker existente; el método NAMO no ejecuta AES/DES.
No se ejecutó SO/Android ni se instalaron NDK, emuladores, Unicorn o paquetes npm.

| Herramienta | Versión observada | Fuente / licencia / uso |
| --- | --- | --- |
| CPython |3.12.14|python.org / PSF / codec, scripts, unittest, venv|
| OpenJDK |17.0.20|openjdk.org / GPL2+Classpath Exception / JADX, strings y oráculo independiente|
| JADX |1.5.6|github.com/skylot/jadx / Apache2 / decompilación estática, JAR verificado|
| Node.js |24.22.1|nodejs.org / MIT/componentes / broker, contrato y regresiones, módulos nativos|
| curl |8.5.0|curl.se / curl license / adquisición HTTPS pública|
| GNU readelf |2.42|gnu.org/software/binutils / GPL3+ / símbolos ELF offline|
| rg/Bash |Versiones capturadas en lock|ripgrep GitHub MIT/Unlicense; GNU Bash GPL / exploración y comandos|
| GitHub, Library y web search |Servicio sin versión expuesta, UNKNOWN|Conectores de Codex / lectura, rama/commit/PR y entrega; no dependencias del codec|

Se creó venv y pip instaló versiones fijadas de Androguard4.1.4,
pyelftools0.33, Capstone5.0.9, Pillow13.0.0 y PyCryptodome3.23.0 con `--report`.
dependencies.lock conserva42 paquetes instalados, transitivas, procedencia y
licencias de metadata;41 distribuciones tienen SHA256 del reporte. Pip del
venv no se descargó en esa operación: hash null/NEEDS_REVIEW. No se publica
el reporte privado completo ni se inventan datos ausentes.

JADX ZIP SHA256545ea2be…e8974 y JAR fe3e12c4…554b completos en lock.
Se usó JAR ya presente y verificado. Preparación de nuevo entorno y descarga
necesitan red; inspección/decompilación/oráculo/pruebas deterministas son offline
tras instalar. Mantener TLS/proxy. Probe Node aquí denegado, sin elusión.

Los scripts propios efectivamente usados están físicamente en tools/, incluidas
revisión fallida de icono, oráculo Java, generador, provisión inline y verificador.
El inventario base es el canónico
`analysis/com.halcon.connect/1391/tools/dependency_inventory.py`; el finalizador
completa fuentes/hashes/commit y el reporte de instalación. No se duplican o
modifican utilidades compartidas `scripts/apk_analysis/`.

Las metadata de licencia no acreditan revisión jurídica transitiva ni aprobación
para autoejecución Fase7. Estado manual: NEEDS_REVIEW/UNREVIEWED_FOR_AUTOMATIC_PHASE7.
El registro central/validador CI exigidos por la política permanecen pendientes.

<!-- PACKAGES -->
| Paquete | Versión | Uso |
| --- | --- | --- |
|alembic|1.20.1|Instalado como parte del entorno/transitivas; no validado por separado.|
|androguard|4.1.4|Manifiesto/APK/certificado; ejecutado.|
|apkInspector|1.3.7|Instalado como parte del entorno/transitivas; no validado por separado.|
|asn1crypto|1.5.1|Instalado como parte del entorno/transitivas; no validado por separado.|
|asttokens|3.0.2|Instalado como parte del entorno/transitivas; no validado por separado.|
|capstone|5.0.9|Desensamblado ARM64 offline; ejecutado.|
|cffi|2.1.1|Instalado como parte del entorno/transitivas; no validado por separado.|
|click|8.5.0|Instalado como parte del entorno/transitivas; no validado por separado.|
|colorama|0.4.6|Instalado como parte del entorno/transitivas; no validado por separado.|
|cryptography|50.0.2|Instalado como parte del entorno/transitivas; no validado por separado.|
|dataset|2.0.0|Instalado como parte del entorno/transitivas; no validado por separado.|
|executing|2.3.0|Instalado como parte del entorno/transitivas; no validado por separado.|
|ipython|9.18.1|Instalado como parte del entorno/transitivas; no validado por separado.|
|ipython_pygments_lexers|1.1.1|Instalado como parte del entorno/transitivas; no validado por separado.|
|jedi|0.20.1|Instalado como parte del entorno/transitivas; no validado por separado.|
|loguru|0.7.3|Control de logs del inspector; ejecutado.|
|lxml|6.1.3|Instalado como parte del entorno/transitivas; no validado por separado.|
|Mako|1.4.3|Instalado como parte del entorno/transitivas; no validado por separado.|
|MarkupSafe|3.0.4|Instalado como parte del entorno/transitivas; no validado por separado.|
|matplotlib-inline|0.2.2|Instalado como parte del entorno/transitivas; no validado por separado.|
|mutf8|1.1.0|Instalado como parte del entorno/transitivas; no validado por separado.|
|networkx|3.7|Instalado como parte del entorno/transitivas; no validado por separado.|
|parso|0.8.7|Instalado como parte del entorno/transitivas; no validado por separado.|
|pexpect|4.9.0|Instalado como parte del entorno/transitivas; no validado por separado.|
|pillow|13.0.0|Formato/dimensiones del PNG; ejecutado.|
|pip|25.0.1|Instalado como parte del entorno/transitivas; no validado por separado.|
|prompt_toolkit|3.0.53|Instalado como parte del entorno/transitivas; no validado por separado.|
|psutil|7.2.2|Instalado como parte del entorno/transitivas; no validado por separado.|
|ptyprocess|0.7.0|Instalado como parte del entorno/transitivas; no validado por separado.|
|pure_eval|0.2.4|Instalado como parte del entorno/transitivas; no validado por separado.|
|pycparser|3.12|Instalado como parte del entorno/transitivas; no validado por separado.|
|pycryptodome|3.23.0|Instalado como parte del entorno/transitivas; no validado por separado.|
|pydot|4.0.1|Instalado como parte del entorno/transitivas; no validado por separado.|
|pyelftools|0.33|ELF/rodata offline; ejecutado.|
|Pygments|2.21.0|Instalado como parte del entorno/transitivas; no validado por separado.|
|pyparsing|3.3.3|Instalado como parte del entorno/transitivas; no validado por separado.|
|PyYAML|6.0.3|Instalado como parte del entorno/transitivas; no validado por separado.|
|SQLAlchemy|2.1.8|Instalado como parte del entorno/transitivas; no validado por separado.|
|stack-data|0.6.3|Instalado como parte del entorno/transitivas; no validado por separado.|
|traitlets|5.16.1|Instalado como parte del entorno/transitivas; no validado por separado.|
|typing_extensions|4.16.0|Instalado como parte del entorno/transitivas; no validado por separado.|
|wcwidth|0.9.4|Instalado como parte del entorno/transitivas; no validado por separado.|

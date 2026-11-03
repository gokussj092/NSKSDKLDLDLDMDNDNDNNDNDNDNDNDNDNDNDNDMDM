# Herramientas, librerías y procedencia

Investigación manual Linux x86_64, CPython aislado. El método operativo usa
biblioteca estándar y la primitiva compartida ya existente de BD_NET_VPN.
No se instalaron paquetes npm, emuladores, NDK, Unicorn ni herramientas de
fuerza bruta para este método. El SO solo fue inspeccionado offline.

| Herramienta | Versión realmente usada | Fuente oficial / licencia / uso |
| --- | --- | --- |
| CPython |3.12.14|python.org / PSF / scripts, stdlib, unittest, inventario|
| OpenJDK |17.0.20|openjdk.org / GPL2 con Classpath Exception / JADX, strings y oráculo independiente|
| JADX |1.5.6|github.com/skylot/jadx / Apache2 / decompilación estática; ZIP/JAR SHA256 en lock|
| Node.js |24.22.1|nodejs.org / MIT y componentes / pruebas del broker/contrato, módulos nativos|
| curl |8.5.0|curl.se / curl license / descarga pública inicial, TLS del entorno|
| GNU readelf |2.42|gnu.org/software/binutils / GPL3+ / símbolos ELF offline|
| rg y shell |Versión no retenida, NEEDS_REVIEW|github.com/BurntSushi/ripgrep / MIT o Unlicense; GNU Bash GPL / búsquedas y orquestación|
| GitHub connector |Versión de servicio no expuesta, UNKNOWN|Conexión del repositorio / lectura de fuentes y posterior commit con lease; no dependencia operativa|

Todas las versiones PyPI instaladas, dependencias declaradas, metadata de
origen y licencias se conservan en `dependencies.lock.json`; instalación exacta
por versiones en `requirements.lock.txt`. Las42 distribuciones no equivalen a
42 librerías del codec ni a42 ejecuciones certificadas por separado. Los
hashes de archivos de distribución no se conservaron durante instalación:
null/NEEDS_REVIEW, sin datos inventados. Las fuentes/hashes de los scripts
propios y canónicos compartidos sí están fijados. Los binarios de terceros no
se redistribuyen en el expediente.

`decompile.py` fija JADX ZIP
`545ea2be9c242511bc145755cf4bda2485ade42966e096f8b4d3da2a230e8974`
y JAR `fe3e12c45acf75f92369685fd02d1d7a7323385dc725680a9b98a0dac0ea554b`.
Se usó el JAR previamente almacenado y verificado. Java/Node/Python se ejecutan
localmente; solo adquisición, preparación nueva de JADX/PyPI y updater necesitan
red. Mantener TLS/proxy del entorno. Falta permiso de red Node en este ejecutor;
no se intentó eludirlo.

Herramientas propias efectivamente usadas: `prepare.py`, `recover.py`, su
revisión fallida conservada, `make_vectors.py`, `verify.py`, `probe_node.mjs`,
`run_checks.py` y `finalize.py`. Las utilidades compartidas (`inspect_apk`, JADX,
LSParanoid, ELF, referencias Java y `bd_net_verify.java_batch`) quedan canónicas,
sin modificación, con hash/commit en el lock. El inventario inicial se ejecutó
con `analysis/com.halcon.connect/1391/tools/dependency_inventory.py`; el
finalizador agrega las herramientas efectivamente consumidas aquí.

Las licencias transitivas requieren revisión. Estas herramientas no se declaran
APPROVED para autoejecución Fase7. La política de evidencia es vigente, pero el
validador CI/registro central de aprobaciones continúan pendientes de código.

<!-- PACKAGES -->
| Paquete | Versión | Uso |
| --- | --- | --- |
|alembic|1.20.1|Instalado como parte del entorno/transitivas; no validado por separado.|
|androguard|4.1.4|Manifiesto/APK; ejecutado.|
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
|loguru|0.7.3|Inspector desactiva logs Androguard; ejecutado.|
|lxml|6.1.3|Instalado como parte del entorno/transitivas; no validado por separado.|
|Mako|1.4.3|Instalado como parte del entorno/transitivas; no validado por separado.|
|MarkupSafe|3.0.4|Instalado como parte del entorno/transitivas; no validado por separado.|
|matplotlib-inline|0.2.2|Instalado como parte del entorno/transitivas; no validado por separado.|
|mutf8|1.1.0|Instalado como parte del entorno/transitivas; no validado por separado.|
|networkx|3.7|Instalado como parte del entorno/transitivas; no validado por separado.|
|parso|0.8.7|Instalado como parte del entorno/transitivas; no validado por separado.|
|pexpect|4.9.0|Instalado como parte del entorno/transitivas; no validado por separado.|
|pillow|13.0.0|Dimensiones del icono; ejecutado.|
|pip|25.0.1|Instalado como parte del entorno/transitivas; no validado por separado.|
|prompt_toolkit|3.0.53|Instalado como parte del entorno/transitivas; no validado por separado.|
|psutil|7.2.2|Instalado como parte del entorno/transitivas; no validado por separado.|
|ptyprocess|0.7.0|Instalado como parte del entorno/transitivas; no validado por separado.|
|pure_eval|0.2.4|Instalado como parte del entorno/transitivas; no validado por separado.|
|pycparser|3.12|Instalado como parte del entorno/transitivas; no validado por separado.|
|pycryptodome|3.23.0|Instalado como parte del entorno/transitivas; no validado por separado.|
|pydot|4.0.1|Instalado como parte del entorno/transitivas; no validado por separado.|
|pyelftools|0.33|Lectura ELF offline; ejecutado.|
|Pygments|2.21.0|Instalado como parte del entorno/transitivas; no validado por separado.|
|pyparsing|3.3.3|Instalado como parte del entorno/transitivas; no validado por separado.|
|PyYAML|6.0.3|Instalado como parte del entorno/transitivas; no validado por separado.|
|SQLAlchemy|2.1.6|Instalado como parte del entorno/transitivas; no validado por separado.|
|stack-data|0.6.3|Instalado como parte del entorno/transitivas; no validado por separado.|
|traitlets|5.16.1|Instalado como parte del entorno/transitivas; no validado por separado.|
|typing_extensions|4.16.0|Instalado como parte del entorno/transitivas; no validado por separado.|
|wcwidth|0.9.4|Instalado como parte del entorno/transitivas; no validado por separado.|

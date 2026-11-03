# Dependencias y ejecución real

Entorno aislado de investigación Linux x86_64. No se ejecutó APK/SO, no se
instalaron dependencias desde la APK ni se usó fuerza bruta. Revisión de
licencias transitivas pendiente; herramientas **no aprobadas para autoejecución
Fase7**. El registro CI obligatorio sigue pendiente de implementación.

| Herramienta | Versión observada | Uso / fuente / licencia |
| --- | --- | --- |
| CPython |3.12.14|Scripts/unittest/stdlib, python.org, PSF|
| Java/OpenJDK |17.0.20|Oráculo independiente XXTEA; openjdk.org, GPL2+Classpath Exception|
| JADX |1.5.6|Fuente estática; github.com/skylot/jadx; Apache2; ZIP/JAR con hashes verificados por decompile.py|
| Node.js |24.22.1|Broker y contrato; nodejs.org; MIT/componentes; módulos nativos, sin instalar npm|
| curl |8.5.0|Descarga inicial pública; curl.se; curl license; red/TLS del entorno|
| rg/readelf/utilidades |Versiones del ejecutor no fijadas, NEEDS_REVIEW|Exploración local; no dependencias nuevas del método|

El motor operativo reutiliza ZiG_Tunnel/codec.py y los validadores de
HTTP_FenixVPN sin modificarlos. PyCryptodome se carga por esa dependencia;
el catálogo XXTEA no ejecuta AES/DES. El oráculo Java es el archivo canónico
existente tests/golden/zig_oracle.java, con clave/delta comprobados contra
FileUtils/XxTea del APK. No se copian fuentes ni binarios de terceros.

Los42 paquetes instalados se fijan en requirements.lock.txt y dependencies.lock.json.
Las URLs/licencias del lock son metadata de distribución y requieren revisión;
los hashes de wheels no se conservaron durante pip install: null/NEEDS_REVIEW.
No se inventan hashes o versiones. Los hashes de scripts/fixtures sí se registran.

| Paquete | Versión | Estado de uso |
| --- | --- | --- |
|alembic|1.20.1|Transitiva instalada; no ejecutada ni validada por separado.|
|androguard|4.1.4|Manifiesto/inspección estática del APK; ejecutado.|
|apkInspector|1.3.7|Transitiva instalada; no ejecutada ni validada por separado.|
|asn1crypto|1.5.1|Transitiva instalada; no ejecutada ni validada por separado.|
|asttokens|3.0.2|Transitiva instalada; no ejecutada ni validada por separado.|
|capstone|5.0.9|Instalado, no requerido por el método final.|
|cffi|2.1.1|Transitiva instalada; no ejecutada ni validada por separado.|
|click|8.5.0|Transitiva instalada; no ejecutada ni validada por separado.|
|colorama|0.4.6|Transitiva instalada; no ejecutada ni validada por separado.|
|cryptography|50.0.2|Transitiva instalada; no ejecutada ni validada por separado.|
|dataset|2.0.0|Transitiva instalada; no ejecutada ni validada por separado.|
|executing|2.3.0|Transitiva instalada; no ejecutada ni validada por separado.|
|ipython|9.18.1|Transitiva instalada; no ejecutada ni validada por separado.|
|ipython_pygments_lexers|1.1.1|Transitiva instalada; no ejecutada ni validada por separado.|
|jedi|0.20.1|Transitiva instalada; no ejecutada ni validada por separado.|
|loguru|0.7.3|Logs Androguard desactivados por el inspector.|
|lxml|6.1.3|Transitiva instalada; no ejecutada ni validada por separado.|
|Mako|1.4.3|Transitiva instalada; no ejecutada ni validada por separado.|
|MarkupSafe|3.0.4|Transitiva instalada; no ejecutada ni validada por separado.|
|matplotlib-inline|0.2.2|Transitiva instalada; no ejecutada ni validada por separado.|
|mutf8|1.1.0|Transitiva instalada; no ejecutada ni validada por separado.|
|networkx|3.7|Transitiva instalada; no ejecutada ni validada por separado.|
|parso|0.8.7|Transitiva instalada; no ejecutada ni validada por separado.|
|pexpect|4.9.0|Transitiva instalada; no ejecutada ni validada por separado.|
|pillow|13.0.0|Transitiva instalada; no ejecutada ni validada por separado.|
|pip|25.0.1|Instalación/listado del entorno.|
|prompt_toolkit|3.0.53|Transitiva instalada; no ejecutada ni validada por separado.|
|psutil|7.2.2|Transitiva instalada; no ejecutada ni validada por separado.|
|ptyprocess|0.7.0|Transitiva instalada; no ejecutada ni validada por separado.|
|pure_eval|0.2.4|Transitiva instalada; no ejecutada ni validada por separado.|
|pycparser|3.12|Transitiva instalada; no ejecutada ni validada por separado.|
|pycryptodome|3.23.0|Importado por los validadores compartidos del runtime.|
|pydot|4.0.1|Transitiva instalada; no ejecutada ni validada por separado.|
|pyelftools|0.33|Instalado, no requerido por el método final.|
|Pygments|2.21.0|Transitiva instalada; no ejecutada ni validada por separado.|
|pyparsing|3.3.3|Transitiva instalada; no ejecutada ni validada por separado.|
|PyYAML|6.0.3|Transitiva instalada; no ejecutada ni validada por separado.|
|SQLAlchemy|2.1.6|Transitiva instalada; no ejecutada ni validada por separado.|
|stack-data|0.6.3|Transitiva instalada; no ejecutada ni validada por separado.|
|traitlets|5.16.1|Transitiva instalada; no ejecutada ni validada por separado.|
|typing_extensions|4.16.0|Transitiva instalada; no ejecutada ni validada por separado.|
|wcwidth|0.9.4|Transitiva instalada; no ejecutada ni validada por separado.|

Los scripts de adquisición, censo, generación sintética, verificación real y
transporte Node se conservan en tools/. Los canónicos y sus hashes/commit están
en MANIFEST y dependencies.lock. La provisión de claves no cambió: se usa la
misma receta de formato ya existente, sin nuevas variables Compose.

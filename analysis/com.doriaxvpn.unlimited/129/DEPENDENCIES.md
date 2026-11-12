# Dependencias y herramientas

Entorno reutilizado Linux x86_64, Python aislado. El codec usa PyCryptodome3.23.0
(Crypto.Cipher.AES/Crypto.Util.Padding) y validación JSON canónica BD_NET_VPN.
Androguard/Loguru inspeccionan APK, recursos, certificado y Dalvik; Pillow valida
el PNG. No se ejecutan SO/guards/licencia, ni se usan NDK/emuladores/Unicorn,
fuerza bruta o paquetes npm. Pyelftools/Capstone están instalados del entorno
anterior pero no se necesitan para este método.

| Herramienta | Versión ejecutada | Origen /licencia /propósito |
| --- | --- | --- |
|CPython|3.12.14|python.org /PSF /codec, scripts, unittest, urllib, gzip, UUID|
|OpenJDK|17.0.20|openjdk.org /GPL2+Classpath Exception /JADX y JCA independiente|
|JADX|1.5.6|github.com/skylot/jadx /Apache2 /fuentes estáticas, JAR comprobado|
|Node.js|24.22.1|nodejs.org /MIT y componentes /broker, contratos y pruebas|
|curl|8.5.0|curl.se /curl license /adquisición HTTPS de APK|
|rg/Bash|Versiones en lock|ripgrep GitHub MIT/Unlicense; GNU Bash GPL /exploración y comandos|
|Conectores GitHub/Library/web search|Versión de servicio no expuesta, UNKNOWN|Servicios de Codex, no parte del runtime del codec|

42 distribuciones instaladas se fijan en requirements.lock y dependencies.lock.
41 hashes de distribución proceden del reporte real de instalación de NAMO,
guardados en su lock versionado: se reutilizan solo con nombre/versión iguales,
con ruta y SHA256 de esa fuente. Este método no reinstaló paquetes. Pip del
venv no tiene hash de archivo de distribución retenido: null/NEEDS_REVIEW.
No se inventan valores ni se afirma validada cada transitiva por separado.

JADX ZIP/JAR tienen SHA256 completos en el lock, verificados por el launcher.
Se usó JAR ya disponible. Adquisición, Firebase y catálogo requieren red;
inspección/JCA/pruebas son offline tras preparar dependencias. Mantener TLS/proxy.
Solo hubo una instalación Firebase analítica, token emitido por FIS y borrado200;
no se fabricaron pruebas de integridad ni se invocaron cuentas o licencias.

Scripts propios utilizados están físicamente en tools/, con revisiones fallidas
y receta por build. `scripts/apk_analysis/inspect_apk.py`, `decompile.py` y
`dex_method.py` se conservan canónicos; el último se leyó como referencia del
dump estático y la búsqueda concreta se ejecutó con find_updater.py. No se
redistribuyen binarios JADX ni de la APK. Los shared helpers no se modifican.

Licencias transitivas y aprobación para autoejecución Fase7: NEEDS_REVIEW.
La política documental es obligatoria; el registro central/validador CI aún no
están implementados. Revisión humana y despliegue permanecen separados.

<!-- PACKAGES -->
| Paquete | Versión | Uso |
| --- | --- | --- |
|alembic|1.20.1|Instalado del entorno previo/transitivas; no validado por separado aquí.|
|androguard|4.1.4|APK/recursos/certificado/Dalvik; ejecutado.|
|apkInspector|1.3.7|Instalado del entorno previo/transitivas; no validado por separado aquí.|
|asn1crypto|1.5.1|Instalado del entorno previo/transitivas; no validado por separado aquí.|
|asttokens|3.0.2|Instalado del entorno previo/transitivas; no validado por separado aquí.|
|capstone|5.0.9|Instalado del entorno previo/transitivas; no validado por separado aquí.|
|cffi|2.1.1|Instalado del entorno previo/transitivas; no validado por separado aquí.|
|click|8.5.0|Instalado del entorno previo/transitivas; no validado por separado aquí.|
|colorama|0.4.6|Instalado del entorno previo/transitivas; no validado por separado aquí.|
|cryptography|50.0.2|Instalado del entorno previo/transitivas; no validado por separado aquí.|
|dataset|2.0.0|Instalado del entorno previo/transitivas; no validado por separado aquí.|
|executing|2.3.0|Instalado del entorno previo/transitivas; no validado por separado aquí.|
|ipython|9.18.1|Instalado del entorno previo/transitivas; no validado por separado aquí.|
|ipython_pygments_lexers|1.1.1|Instalado del entorno previo/transitivas; no validado por separado aquí.|
|jedi|0.20.1|Instalado del entorno previo/transitivas; no validado por separado aquí.|
|loguru|0.7.3|Logs del inspector controlados; ejecutado.|
|lxml|6.1.3|Instalado del entorno previo/transitivas; no validado por separado aquí.|
|Mako|1.4.3|Instalado del entorno previo/transitivas; no validado por separado aquí.|
|MarkupSafe|3.0.4|Instalado del entorno previo/transitivas; no validado por separado aquí.|
|matplotlib-inline|0.2.2|Instalado del entorno previo/transitivas; no validado por separado aquí.|
|mutf8|1.1.0|Instalado del entorno previo/transitivas; no validado por separado aquí.|
|networkx|3.7|Instalado del entorno previo/transitivas; no validado por separado aquí.|
|parso|0.8.7|Instalado del entorno previo/transitivas; no validado por separado aquí.|
|pexpect|4.9.0|Instalado del entorno previo/transitivas; no validado por separado aquí.|
|pillow|13.0.0|Formato/dimensiones PNG; ejecutado.|
|pip|25.0.1|Instalado del entorno previo/transitivas; no validado por separado aquí.|
|prompt_toolkit|3.0.53|Instalado del entorno previo/transitivas; no validado por separado aquí.|
|psutil|7.2.2|Instalado del entorno previo/transitivas; no validado por separado aquí.|
|ptyprocess|0.7.0|Instalado del entorno previo/transitivas; no validado por separado aquí.|
|pure_eval|0.2.4|Instalado del entorno previo/transitivas; no validado por separado aquí.|
|pycparser|3.12|Instalado del entorno previo/transitivas; no validado por separado aquí.|
|pycryptodome|3.23.0|AES-CBC/GCM y tags; runtime ejecutado.|
|pydot|4.0.1|Instalado del entorno previo/transitivas; no validado por separado aquí.|
|pyelftools|0.33|Instalado del entorno previo/transitivas; no validado por separado aquí.|
|Pygments|2.21.0|Instalado del entorno previo/transitivas; no validado por separado aquí.|
|pyparsing|3.3.3|Instalado del entorno previo/transitivas; no validado por separado aquí.|
|PyYAML|6.0.3|Instalado del entorno previo/transitivas; no validado por separado aquí.|
|SQLAlchemy|2.1.8|Instalado del entorno previo/transitivas; no validado por separado aquí.|
|stack-data|0.6.3|Instalado del entorno previo/transitivas; no validado por separado aquí.|
|traitlets|5.16.1|Instalado del entorno previo/transitivas; no validado por separado aquí.|
|typing_extensions|4.16.0|Instalado del entorno previo/transitivas; no validado por separado aquí.|
|wcwidth|0.9.4|Instalado del entorno previo/transitivas; no validado por separado aquí.|

## Revisión automática 2026-11-04

Sin paquetes nuevos: el cliente utiliza urllib/gzip/secrets/threading/time y JSON de stdlib; Node crypto/zlib/HTTPS/DNS nativos. Mismas versiones fijadas en lock; el finalizador comprueba las 42 distribuciones instaladas. Las opciones Android públicas se extraen con Androguard existente, no se instala Firebase SDK/npm ni Admin SDK. Nuevos scripts físicos y ejecución en tools/refresh, referencias y hashes en MANIFEST. Los tokens FIS emitidos no son constantes: viven solo en memoria y no se publican.

# Herramientas, versiones y reutilización

Se reutilizó el venv de investigación existente, sin instalar dependencias nuevas: Python3.12.14 (PSF), Androguard4.1.3 (Apache2) para AXML/certificado, PyCryptodome3.23.0 (BSD2/componentes dominio público) para el lector. JADX1.5.6 completo (Apache2) ejecutó análisis estático sobre OpenJDK21.0.13 (GPL2+Classpath). Java/JCA propio comprueba independientemente ambas capas. Node24.22.1 (MIT), Node22 en CI, prueba el broker y el catálogo web. Linux AMD64. Fuentes oficiales y las54 distribuciones del entorno con versiones/licencias conocidas están en dependencies.lock.json y requirements.lock.txt; estar instalado no equivale a utilizado. Los módulos Frida/Capstone/ELF no se ejecutaron; Argon2 solo se usa en regresiones de otros proveedores.

## Herramientas compartidas sin modificaciones

- scripts/apk_analysis/decompile.py: instalador fijado de JADX1.5.6, checksum en lockfile; se reutilizó la caché verificada, sin descarga nueva.
- analysis/_intake/austro-cat-2026-11-09/tools/decompile.py: misma receta JADX completo auto/no-res/Xmx2200m/j3.
- decoders/Python/apps/BD_NET_VPN/codec.py: validación/render estricto de JSON; no cambia su interfaz ni contenido.

JADX JAR SHA-256fe3e12c45acf75f92369685fd02d1d7a7323385dc725680a9b98a0dac0ea554b; ZIP545ea2be9c242511bc145755cf4bda2485ade42966e096f8b4d3da2a230e8974; origen https://github.com/skylot/jadx/releases/tag/v1.5.6. Python https://python.org/; Androguard https://github.com/androguard/androguard; PyCryptodome https://pycryptodome.org/; Java https://openjdk.org/; Node https://nodejs.org/.

## Herramientas propias conservadas

El intake APKS nuevo, su wrapper por build, inspect_apk.py, probe.py, ProOracle.java, verify.py y make_fixture.py se guardan físicamente. Hashes e interfaces en el lockfile. Son recetas de investigación manual, no herramientas aprobadas para ejecución automática en producción. No se utiliza el script aportado de Litron base para decodificar Pro ni el acquirer de TunnelDoom. Los binarios de herramientas, APK, fuentes decompiladas y catálogos reales no se redistribuyen. Licencias transitivas desconocidas siguen UNKNOWN_NEEDS_REVIEW; ningún registro concede aprobación automática.

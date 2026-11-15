# Herramientas, librerías y reutilización — build15

No se instaló ninguna dependencia nueva. Python3.12.14/Linux AMD64; catálogo operativo usa biblioteca estándar y ec.py; PyCryptodome3.23.0 conserva los archivos anteriores. Androguard4.1.3 lee identidad; Java/JADX y el resolver propio inspeccionan fuentes sin ejecutar APK. Node24.22.1 local, Node22 en CI.

| Herramienta | Versión | Procedencia y licencia |
| --- | --- | --- |
| Androguard | 4.1.3 | https://github.com/androguard/androguard — Apache-2.0 |
| JADX completo | 1.5.6 | https://github.com/skylot/jadx — Apache-2.0 |
| OpenJDK | 21.0.13+9 Debian | https://openjdk.org — GPL2 con Classpath Exception |
| PyCryptodome | 3.23.0 | https://www.pycryptodome.org — BSD2 / componentes dominio público |
| Node.js | 24.22.1 /22 CI | https://nodejs.org — MIT |

## Reutilizados sin cambios

- analysis/com.tunneldoom.http/432/tools/acquire.py — SHA-256 7d8091243a8097fbaede447706aca4a0bcc03522a347396e20fe6075e5e8864b
- scripts/apk_analysis/decompile.py — SHA-256 dd04a05c2cb46bae494af412733d9e27b71167fc86f787371e76dfbddd50a3dd
- scripts/apk_analysis/random_strings.py — SHA-256 639cad8a7506794c9612a387ade3d3449c3e23f2ae4b17eced140657ba3d3b75
- tests/golden/austroplus_oracle.java — SHA-256 6708eb41f3dfe444e7d66b1984ca61a7829e175c4b9295311fd47e776cb7295f
- tests/golden/austroplus_vectors.json — SHA-256 9d18982f901767c336427e9c293287e9f25c20b380f3b2bb769110728a680d8c
- decoders/Python/ec.py — SHA-256 8c4efb1e02f9273fa0cd2368c6e44176236a5be471c48a5e9f6a5fb4bf53eb53

El adquisidor y la receta JADX de analysis/_intake/austro-cat-2026-11-09/tools son wrappers propios nuevos conservados; tools/acquire.py fija la build. inspect_apk.py, inspect_v1.py, probe.py, verify.py y make_fixture.py son herramientas propias por build. No se copian JAR, APK ni fuentes del proveedor.

El lock enumera los54 paquetes Python del entorno reutilizado; no significa que todos se ejecutaron. Capstone, pyelftools, Frida y Argon2 no intervienen en el algoritmo de catálogo AustroPlus. Licencias de transitivas desconocidas permanecen UNKNOWN_NEEDS_REVIEW, sin aprobación humana automática. Los scripts y nuevas recetas no se registran como herramientas aprobadas del arnés automático.

La instantánea local tenía un salto de línea final adicional en tres helpers. Se comprobó igualdad exacta al quitar solo finales de línea y se restauró el texto Git canónico. El lock registra los checksums de ambas representaciones y generated/provenance-normalization.json conserva la comparación. Se repitieron identidad, verificación del instalador y JCA con las fuentes canónicas; los helpers compartidos no se modifican en este commit.

# Dependencias, herramientas y reutilización

Entorno de investigación observado: Python 3.12.14, JDK21 y Linux AMD64. La ejecución automática del arnés APK no recibe estas herramientas nuevas por este cambio.

| Herramienta | Versión | Uso / procedencia | Licencia declarada |
| --- | --- | --- | --- |
| androguard | 4.1.3 | https://github.com/androguard/androguard | Apache-2.0 |
| argon2-cffi | 25.1.0 | https://github.com/hynek/argon2-cffi | MIT |
| argon2-cffi-bindings | 26.1.0 | https://github.com/hynek/argon2-cffi-bindings | MIT |
| capstone | 5.0.6 | https://www.capstone-engine.org/ | BSD-3-Clause |
| pycryptodome | 3.23.0 | https://www.pycryptodome.org/ | BSD-2-Clause / Public-Domain components |
| pyelftools | 0.32 | https://github.com/eliben/pyelftools | Public-Domain |
| JADX | 1.5.6 | https://github.com/skylot/jadx/releases/tag/v1.5.6 | Apache-2.0 |
| OpenJDK | 21.0.13 | https://openjdk.org/ | GPL-2.0-with-Classpath-exception |
| Node.js | 24.22.1 (local research tests); 22 in CI | https://nodejs.org/ | MIT |

Todas las distribuciones Python directas/transitivas realmente instaladas (incluidas herramientas no ejecutadas) se registran con versión y origen en dependencies.lock.json y requirements.lock.txt. Los metadatos de licencia desconocidos quedan UNKNOWN_NEEDS_REVIEW; no se presentan como aprobación humana. Frida puede aparecer como dependencia transitiva de Androguard: no se utilizó ni se ejecutó la app.

## Fuentes compartidas conservadas

- analysis/com.tunneldoom.http/432/tools/acquire.py — SHA-256 1fbaa2243eacdfaf4404d7ea07886e9432262010bebf3595d51240097c37ed8b; sin cambios.
- scripts/apk_analysis/decompile.py — SHA-256 00b5d0ab68b9a46a5bd18ab0160c755adbfa180e81de0625b9dc8203f1c5036c; sin cambios.
- tests/golden/tunneltweak_oracle.java — SHA-256 dd7438287ba357b5a83f2d25eed16ca7e97e10c34d659d9af3e5d0152acd9226; sin cambios.
- tests/golden/tunneltweak_vectors.json — SHA-256 d7d789ed15183e0e157f46cb039cf2adc01d593c064d8effaf860ef634f2039c; sin cambios.

El extractor usa Androguard para leer AXML/certificados, no para ejecutar DEX. Los JAR/compiladores se descargan desde su fuente oficial y se verifican; no se guardan binarios ajenos en Git. Los scripts propios quedan completos en tools/.

El oráculo Java/JCA existente se reutilizó sin cambios. El algoritmo público del catálogo coincide con build51; la solicitud HTTP se actualizó al build53.

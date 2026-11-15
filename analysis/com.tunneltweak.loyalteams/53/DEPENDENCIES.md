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

- analysis/com.tunneldoom.http/432/tools/acquire.py — SHA-256 7d8091243a8097fbaede447706aca4a0bcc03522a347396e20fe6075e5e8864b; sin cambios.
- scripts/apk_analysis/decompile.py — SHA-256 dd04a05c2cb46bae494af412733d9e27b71167fc86f787371e76dfbddd50a3dd; sin cambios.
- tests/golden/tunneltweak_oracle.java — SHA-256 5df4031f6c59b43f644cc07fa519c423726ef327ef5ed053604a4efb7b26f109; sin cambios.
- tests/golden/tunneltweak_vectors.json — SHA-256 d7d789ed15183e0e157f46cb039cf2adc01d593c064d8effaf860ef634f2039c; sin cambios.

El extractor usa Androguard para leer AXML/certificados, no para ejecutar DEX. Los JAR/compiladores se descargan desde su fuente oficial y se verifican; no se guardan binarios ajenos en Git. Los scripts propios quedan completos en tools/.

El oráculo Java/JCA existente se reutilizó sin cambios. El algoritmo público del catálogo coincide con build51; la solicitud HTTP se actualizó al build53.

## Historial de builds: reutilización 2026-11-09

Implementación nueva exclusivamente con módulos estándar Node/Python (fs/path/crypto, json/os/urllib/time). Sin dependencias de terceros añadidas, sin descarga de herramientas en runtime. El oráculo JCA previo se reutilizó sin cambios para probar el catálogo recuperado. Node y Python comparten JSONschema/seed y lock por creación exclusiva; no dependen de Redis para este estado. Los checksums y versiones anteriores se conservan, más la revisión en el lock. verify_auto_builds.py es el wrapper propio nuevo; la implementación canónica está en cloud/web/lib/tunneltweak-builds.mjs y decoders/Python/apps/Tunneltweak/build_history.py para evitar copias divergentes.

La instantánea local tenía un salto de línea final adicional en tres helpers. Se comprobó igualdad exacta al quitar solo finales de línea y se restauró el texto Git canónico. El lock registra los checksums de ambas representaciones y generated/provenance-normalization.json conserva la comparación. Se repitieron identidad, verificación del instalador y JCA con las fuentes canónicas; los helpers compartidos no se modifican en este commit.

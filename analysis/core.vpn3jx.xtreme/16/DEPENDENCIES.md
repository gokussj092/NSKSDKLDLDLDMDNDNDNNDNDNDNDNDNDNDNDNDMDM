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
| Go | 1.27.3 | https://go.dev/dl/ | BSD-3-Clause |
| golang.org/x/crypto | v0.36.0 | https://pkg.go.dev/golang.org/x/crypto@v0.36.0 | BSD-3-Clause |
| golang.org/x/sys | v0.31.0 | https://pkg.go.dev/golang.org/x/sys@v0.31.0 | BSD-3-Clause |

Todas las distribuciones Python directas/transitivas realmente instaladas (incluidas herramientas no ejecutadas) se registran con versión y origen en dependencies.lock.json y requirements.lock.txt. Los metadatos de licencia desconocidos quedan UNKNOWN_NEEDS_REVIEW; no se presentan como aprobación humana. Frida puede aparecer como dependencia transitiva de Androguard: no se utilizó ni se ejecutó la app.

## Fuentes compartidas conservadas

- analysis/com.tunneldoom.http/432/tools/acquire.py — SHA-256 1fbaa2243eacdfaf4404d7ea07886e9432262010bebf3595d51240097c37ed8b; sin cambios.
- scripts/apk_analysis/decompile.py — SHA-256 00b5d0ab68b9a46a5bd18ab0160c755adbfa180e81de0625b9dc8203f1c5036c; sin cambios.
- scripts/apk_analysis/paranoid_strings.py — SHA-256 8e31e9b8622b9d0204c419490e1dbdc1bc4978f8f06e4470a900a5bc97803b48; sin cambios.
- scripts/apk_analysis/go_inspect.py — SHA-256 65998c2cc4052fc8f244f5682cb1dc794b225ed1dae79ee24601dd26f64bdf8a; sin cambios.
- scripts/apk_analysis/elf_inspect.py — SHA-256 72c4b2ae4b8ad3b007abfae2f5e5e622a05278c39771a13dd195f72c71fa0824; sin cambios.
- scripts/apk_analysis/wolf_native_constants.py — SHA-256 6b00ba98995adb990a23d2e437f4612268051e0b32331cfd019451af90143873; sin cambios.
- scripts/apk_analysis/wolf_verify.py — SHA-256 e119e95aed3cf3f1be15c56f6f3653a9fee8b07d6891e54dd1dbac32d423da3d; sin cambios.
- tests/golden/wolf_oracle.java — SHA-256 9fa80a1dd7aeb80713729948960acfa72389ca7d26fc5bb132c6deac1a5907a7; sin cambios.

El extractor usa Androguard para leer AXML/certificados, no para ejecutar DEX. Los JAR/compiladores se descargan desde su fuente oficial y se verifican; no se guardan binarios ajenos en Git. Los scripts propios quedan completos en tools/.

El oráculo Go es nuevo y usa go.mod/go.sum fijados. Los lectores ARM64 anteriores se consultaron y se conservan; native_inspect.py es la adaptación ARM32 utilizada.

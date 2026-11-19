# Dependencias — SSC Custom (dev.epro.ssc, 96)

Inventario de todo lo usado realmente en esta investigación, según
§2.1 de `analysis/METHOD_EVIDENCE_POLICY.md`. La instalación
automática sigue DESHABILITADA; esto es solo documentación.

## Herramientas propias (en este dossier)

| Nombre | Propósito | Versión | Lenguaje | Red | Licencia |
| --- | --- | --- | --- | --- | --- |
| `tools/ssc_oracle.py` | Reimplementación independiente del algoritmo SSC (cifrador + decodificador) | 1.0 (este dossier) | Python | No | Propia |
| `tools/make_fixtures.py` | Genera fixtures sintéticos + JSON esperado | 1.0 | Python | No | Propia |
| `tools/verify.py` | Oráculo vs decodificador del servidor, 24 checks | 1.0 | Python | No | Propia |
| `tools/host_ssc_test.cpp` | Harness: C++ de producción vs JSON esperado, 12 checks | 1.0 | C++17 | No | Propia |
| `tools/build_host_harness.sh` | Compila y corre el harness | 1.0 | bash | Solo descarga fijada de `json.hpp` (con fallback local) | Propia |
| `tests/test_method.py` | Tests `unittest` del dossier | 1.0 | Python | No | Propia |

## Herramientas y librerías de terceros

| Nombre | Propósito | Versión usada | Origen oficial | Licencia | Sistema/ABI | Red | Limitaciones |
| --- | --- | --- | --- | --- | --- | --- | --- |
| PyCryptodome | ChaCha20 en el oráculo Python (`Crypto.Cipher.ChaCha20`, nonce 8 bytes, `seek(64)`) | 4.4.0 (venv `~/workspace/http-custom-update/venv`) | https://www.pycryptodome.org | BSD-2-Clause / Apache-2.0 | Python 3.12, x86_64 | No | Solo tiempo de prueba; no se distribuye |
| nlohmann json | Parseo/serialización JSON en el decodificador nativo y el harness | 3.11.3, single header, commit `9cca280a4d0ccf0c08f47a99aa71d1b0e52f8d03`, SHA-256 `9bea4c8066ef4a1c206b2be5a36302f8926f7fdc6087af5d20b417d0cf103ea6` | https://github.com/nlohmann/json | MIT | C++17, header-only, todas las ABI de Android vía CMake FetchContent | Solo descarga fijada (verificada) | Ninguna conocida |
| g++ | Compilación del harness en host | 13.3.0 (Ubuntu 13.3.0-6ubuntu2~24.04.1) | https://gcc.gnu.org | GPL-3.0 (toolchain, no se distribuye) | x86_64 Linux | No | El APK real lo compila CI con el NDK, no este g++ |
| curl | Intentos de descarga del APK en mirrors; descarga fijada de `json.hpp` | sistema | https://curl.se | curl (MIT-like) | x86_64 Linux | Sí | APKPure devolvió 403, APKCombo HTML, APKMirror sin conexión |
| unzip | Disponible para inspección de APK; sin uso (no se pudo descargar el APK) | sistema | https://infozip.sourceforge.io | Info-ZIP | x86_64 Linux | No | — |

## Herramientas compartidas del repo (referenciadas, no modificadas)

| Nombre | Ruta | Uso aquí |
| --- | --- | --- |
| Servidor SSC | `decoders/Python/SSCCUSTOM.py` | Decodificador de referencia; `verify.py` lo ejecuta como oráculo de contraste |
| Port Kotlin | `android/app/src/main/java/com/ghostdeveloper/spdecode/parity/SscPort.kt` + `LegacyChaCha8.kt` | Referencia de la variante ChaCha20-64; el C++ la espeja |
| Generador dorado A23 | `tests/golden/a23_generators.py::ssc_bytes`, `tests/golden/expected/ssc-chacha20.txt` | Formato de una capa ya cubierto en Linux; no reutilizado como fixture (se regeneraron fixtures propios con más casos) |

## No usados (y por qué)

- **apktool / jadx / adb / Android SDK:** no instalados en la VM; el
  APK no se pudo descargar de los mirrors, así que no hubo nada que
  desensamblar. El formato se obtuvo del decodificador del servidor,
  no del APK.
- **Frida / captura en vivo:** fuera de límites por la tarea; no se
  intentó.
- **Mbed TLS:** el decodificador no lo necesita; el ChaCha20 de 64
  bits se implementó a mano (la variante IETF de 96 bits de
  `mbedtls_chacha20_crypt` no es compatible con este formato).

## Revisión

- `nlohmann json` 3.11.3: APPROVED (mismo pin que `CMakeLists.txt`).
- `PyCryptodome` 4.4.0, `g++`, `curl`, `unzip`: NEEDS_REVIEW /
  toolchain del entorno; solo se usan en tiempo de prueba, no se
  distribuyen en el APK (salvo `nlohmann json`, que ya es dependencia
  del proyecto).

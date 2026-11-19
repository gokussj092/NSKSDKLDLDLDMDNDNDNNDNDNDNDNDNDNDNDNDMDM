# DEPENDENCIES — TLS Tunnel 8.5.0 / 516 — OFFLINE

Inventario legible de todo lo usado realmente en esta investigación,
corrección o prueba. Una dependencia citada no significa que esté instalada
o validada más allá de lo registrado en RESULTS.md.

## Herramientas propias

| Nombre | Propósito | Versión | Origen |
|---|---|---|---|
| `decoders/Python/TLS.py` | Oráculo del contenedor TLS (referencia) | repo @ 2996a9b2 | repo SP-DECODE |
| `analysis/.../516/tools/ref_tls.py` | Envoltorio del oráculo para el harness | este expediente | propio |
| `analysis/.../516/tools/make_fixtures.py` | Generador de fixtures sintéticos | este expediente | propio |
| `analysis/.../516/tools/run_harness.py` | Comparación C++ vs oráculo | este expediente | propio |
| `analysis/.../516/tools/host_harness/main.cpp` | Harness host del C++ nativo | este expediente | propio |
| `analysis/.../516/tools/host_harness/CMakeLists.txt` | Build del harness host | este expediente | propio |
| `analysis/.../516/tools/build_host_harness.sh` | Build + run del harness en un paso | este expediente | propio |
| `analysis/.../516/tests/test_method.py` | Tests del expediente (oráculo) | este expediente | propio |
| `android/app/src/main/cpp/spdecode_tls_tunnel.cpp` | Decodificador nativo offline | este expediente | propio |

## Herramientas y librerías de terceros

| Nombre | Propósito | Versión usada | Ecosistema / origen | Licencia | Red |
|---|---|---|---|---|---|
| Python | Runtime del oráculo y las herramientas | 3.12.3 | sistema (Ubuntu 24.04) | PSF | no |
| PyCryptodome (`Crypto`) | AES-GCM del oráculo y de `make_fixtures.py` | 4.4.0 | PyPI (`~/workspace/http-custom-update/venv`) | BSD-2-Clause | no |
| Mbed TLS | AES-256-GCM + Base64 del decodificador nativo y del harness | 3.6.7 (SHA-256 `a7e8bcbec0e6f761b4af24f25677626b35f762f68eef79c08677a363212d11f6`) | https://github.com/Mbed-TLS/mbedtls/releases/download/mbedtls-3.6.7/mbedtls-3.6.7.tar.bz2 | Apache-2.0 | solo descarga fijada (o `SPDECODE_MBEDTLS_ARCHIVE` local) |
| nlohmann/json | Salida JSON del decodificador nativo | 3.11.3 | paquete de sistema `nlohmann-json3-dev` 3.11.3-1; fallback git fijado `9cca280a4d0ccf0c08f47a99aa71d1b0e52f8d03` | MIT | no (fallback: git) |
| g++ | Compilación del harness host | 13.3.0 (Ubuntu 13.3.0-6ubuntu2) | sistema | GPL | no |
| CMake | Configuración del build del harness | 3.28.3 | sistema | BSD-3-Clause | solo FetchContent Mbed TLS |
| curl | Intentos de descarga de la APK 8.5.2 (fallidos, ver ANALYSIS.md §5) | sistema | sistema | MIT | sí (salida bloqueada: 403/000) |
| browser.search / browser.open | Versión en vivo en Play y APKFab | — | herramienta del agente | — | sí (solo lectura de páginas) |

## Notas

- No se usó apktool, jadx ni dexdump: el método ya estaba derivado de la
  APK 8.5.0 en el trabajo previo (`decoders/Python/TLS.py`) y no hizo falta
  re-derivarlo.
- No se usó Frida, captura en vivo ni instrumentación de ningún tipo.
- No se instaló nada en el sistema: el venv Python ya existía
  (`~/workspace/http-custom-update/venv`) y Mbed TLS se descargó solo
  dentro del directorio de build del harness (`/tmp/tls-harness-build`).
- Limitación conocida: el lockfile fija versiones; los hashes de
  distribución solo se conocen para Mbed TLS (verificado por CMake) y el
  single-header json no se descargó en este build (se usó el paquete de
  sistema 3.11.3-1).

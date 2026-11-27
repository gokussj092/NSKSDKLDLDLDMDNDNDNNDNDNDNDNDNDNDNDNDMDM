# Reproducir — port offline n19 (build 942)

Venv Python (oráculo + fixtures):
`~/workspace/http-custom-update/venv/bin/python`
(CPython 3.12.3, PyCryptodome 4.4.0, argon2-cffi 25.1.0).
Toolchain host: g++ 13.3.0, CMake 3.28.3 (el build directo con g++ se usó
aquí; el `CMakeLists.txt` del host harness es el de
`~/workspace/offline-hc942/staging/host_harness_CMakeLists.txt`).

## 0. Archivos de partida

- Base C++ (head remoto feat/version-offline-apk f75c6751…):
  `~/workspace/offline-hc942/staging/spdecode_http_custom.cpp`
  (SHA-256 541f7ec4f7074f5af5c58b287785f22374cfb489).
- Port entregado: `~/workspace/offline-hc942/staging/spdecode_http_custom.cpp.new`
  (SHA-256 6b4e51c8eec020cf1183b3a17fa91f1be541e99569c1fb71de1dd21fa4435c63).
- Legacy companion (fetch remoto, misma rama):
  `android/app/src/main/cpp/spdecode_http_custom_legacy.cpp`
  (SHA-256 a68f71d1c4ee25177fa61237a8bcd015f84d09427a7911c0a36d781895039205).
- Oráculo Python: `dossier942/tools/ref_oracle/` (`codec.py`,
  `crypto.py`, `_hc_hccfg.py`).
- Archivos reales del propietario (rutas privadas, no en el dossier):
  `~/workspace/user/files/test_open_2_7xqg.hc`,
  `test_bloqueo_normal_1_aflj.hc`,
  `test_bloqueo_normal_con_contrase_a_0_m46a.hc`, más los negativos
  `test_solo_whid_*.hc`, `Gjost_0_d9lo.hc`, `884_0_wvd2.hc`.

## 1. Compilar el harness host (misma receta que el dossier 934)

El sistema no tiene instalados los headers de desarrollo
(libmbedtls-dev 2.28.8 es además incompatible: el código exige Mbed TLS
3.6.7). Se usó la librería estática 3.6.7 ya construida por el harness
n15 (`~/workspace/hc-n15-harness-build/_deps/spdecode_mbedtls-build/
library/libmbedcrypto.a`, headers en `.../_deps/spdecode_mbedtls-src/
include`) y los headers de argon2/json extraídos de los .deb en caché:

```sh
mkdir -p /tmp/hc942-build/deps
dpkg-deb -x /var/cache/apt/archives/libargon2-dev_0~20190702+dfsg-4build1_amd64.deb /tmp/hc942-build/deps/argon2
dpkg-deb -x /var/cache/apt/archives/nlohmann-json3-dev_3.11.3-1_all.deb /tmp/hc942-build/deps/json
```

```sh
MBEDTLS_SRC=~/workspace/hc-n15-harness-build/_deps/spdecode_mbedtls-src
MBEDTLS_LIB=~/workspace/hc-n15-harness-build/_deps/spdecode_mbedtls-build/library/libmbedcrypto.a
# .new como spdecode_http_custom.cpp; original como referencia de regresión
g++ -std=c++17 -O2 -Wall -Wextra -Werror -fstack-protector-strong -D_FORTIFY_SOURCE=2 \
  -I <dir-fuentes> -I $MBEDTLS_SRC/include \
  -I /tmp/hc942-build/deps/argon2/usr/include -I /tmp/hc942-build/deps/json/usr/include \
  host_harness_main.cpp spdecode_http_custom.cpp spdecode_http_custom_legacy.cpp \
  $MBEDTLS_LIB /usr/lib/x86_64-linux-gnu/libargon2.so.1 -o hc_harness_n19
# repetir con spdecode_http_custom.cpp (original) -> hc_harness_orig
```

`host_harness_main.cpp` es `~/workspace/offline-hc942/staging/
host_harness_main.cpp` (argv: `<file.hc> [password] [hwid]`; imprime el
JSON o `ERROR <what>` en stderr, exit != 0).

## 2. Archivos reales (oráculo + harness)

```sh
cd ~/workspace/offline-hc942/staging/dossier942/tools
~/workspace/http-custom-update/venv/bin/python run_real_checks.py \
  /tmp/hc942-build/hc_harness_n19 /tmp/hc942-build/hc_harness_orig \
  ~/workspace/user/files
# Esperado: 2 aperturas con py-ref match=True; protegido PASSWORD_REQUIRED /
# AUTH_FAILED; n16 / Gjost / 884 con los mismos errores que el original.
```

## 3. Fixtures sintéticos (rama protegida, HPR1, V4, regresión n15)

```sh
cd ~/workspace/offline-hc942/staging/dossier942/tools
~/workspace/http-custom-update/venv/bin/python make_synthetic_n19.py \
  /tmp/hc942-build/hc_harness_n19 /tmp/hc942-build/hc_harness_orig
# Esperado: ALL OK (12 checks). Fixtures deterministas, sin archivos reales.

# Unit tests sobre los fixtures almacenados:
cd ~/workspace/offline-hc942/staging/dossier942
HC_HARNESS=/tmp/hc942-build/hc_harness_n19 \
HC_HARNESS_ORIG=/tmp/hc942-build/hc_harness_orig \
~/workspace/http-custom-update/venv/bin/python -m unittest tests.test_hc_n19 -v
# Esperado: Ran 8 tests, OK.
```

## 4. Sanitizers (opcional, realizado en esta sesión)

```sh
g++ -std=c++17 -O1 -g -fsanitize=address,undefined -fno-sanitize-recover=all \
  <mismos includes y fuentes que §1> -o hc_harness_asan
./hc_harness_asan ~/workspace/user/files/test_open_2_7xqg.hc > /dev/null
# Esperado: exit 0, stderr vacío.
```

## 5. Regresión con la suite de paridad existente

```sh
cd ~/workspace/spdecode-patch
# CLI con protocolo stdin-frames: compilar native_http_custom_cli.cpp
# (staging) contra el .cpp.new y contra el original, luego:
~/workspace/http-custom-update/venv/bin/python \
  tests/test_offline_hc_native_parity.py /tmp/hc942-build/cli_harness_n19
# En esta sesión: 136 checks OK y fallo idéntico en ambos binarios en el
# caso 'utf8_ignored' (variante legacy de campo; preexistente, ajeno a n19).
# Ver RESULTS.md §4.
```

## 6. Pendiente de verificación (verificador)

1. Abrir `test_bloqueo_normal_con_contrase_a_0_m46a.hc` con su contraseña
   correcta (suministrada en runtime, nunca guardada):
   `./hc_harness_n19 <archivo> <contraseña>` debe imprimir 2 perfiles
   con `app_version` 8.1.5 (942) y el mismo JSON que el oráculo Python
   con la misma contraseña. Esto arbitra además la divergencia de
   composición protegida (ANALYSIS.md §4).
2. Gradle build + import on-device cuando haya SDK/NDK.
3. Confirmar el `.cpp.new` contra el head remoto f75c6751… antes del merge.

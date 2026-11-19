# Reproducir — SSC Custom (dev.epro.ssc, 96)

Todo se ejecuta desde la raíz del repo (el worktree `offline/ssc`).
Python necesario: el venv con PyCryptodome 4.4.0
(`~/workspace/http-custom-update/venv/bin/python` en esta VM, o
cualquier python3 con `pycryptodome>=4.4.0`). No se necesita Android
SDK, ni dispositivo, ni red (salvo la descarga fijada del `json.hpp`
en el harness, que cae de forma segura al header del sistema).

## 1. Regenerar fixtures + expected

```bash
python3 analysis/dev.epro.ssc/96/tools/make_fixtures.py
```

Escribe `tests/fixtures/` (11 archivos) y `tests/expected/` (5 JSON).
Los fixtures son sintéticos y deterministas (sin semilla aleatoria:
los textos planos y las claves están fijados en el script).

## 2. Oráculo Python vs decodificador del servidor

```bash
python3 analysis/dev.epro.ssc/96/tools/verify.py
# Esperado: "verify.py: 24 passed, 0 failed"
```

`verify.py` localiza `decoders/Python/SSCCUSTOM.py` buscando primero
`~/workspace/spdecode-patch` y luego el cwd; para apuntar a otro
checkout: `verify.py --server /ruta/al/repo`.

## 3. Decodificador nativo C++ vs oráculo (host harness)

```bash
bash analysis/dev.epro.ssc/96/tools/build_host_harness.sh
# Esperado: "host_ssc_test: 12 passed, 0 failed"
```

Compila `android/app/src/main/cpp/spdecode_ssc.cpp` **sin cambios**
con `g++ -std=c++17 -O2 -Wall -Wextra -Werror` contra el `json.hpp`
fijado por `CMakeLists.txt` (commit `9cca280a`, SHA-256 verificado;
si la descarga falla, usa `/usr/include/nlohmann/json.hpp`).
El binario queda en `${TMPDIR:-/tmp}/ssc-host-build/host_ssc_test`.

## 4. Todo junto (unittest, stdlib)

```bash
python3 analysis/dev.epro.ssc/96/tests/test_method.py -v
# Esperado: "Ran 3 tests ... OK"
```

## 5. Compilar el APK offline (CI, no en esta VM)

El workflow `offline-native-apk` compila `offdecode` con
`spdecode_ssc.cpp` incluido. Verificación en el teléfono (pendiente):
importar un `.ssc` real exportado por SSC Custom 4.3.13 y un enlace
`ssc://` real; el visor JSON debe mostrar el perfil con las claves
mapeadas (`CONFIGS`, `ADDRESS`, `USERNAME`, ...). Códigos de error
posibles: `SSC_INVALID_HEX`, `SSC_INVALID_L1`, `SSC_INVALID_L2_NONCE`,
`SSC_INVALID_L2`, `SSC_UNSUPPORTED_LAYER`, `SSC_INVALID_INPUT`.

## Entorno fijado

| Herramienta | Versión usada aquí |
| --- | --- |
| PyCryptodome (venv) | 4.4.0 |
| g++ | 13.3.0 (Ubuntu 13.3.0-6ubuntu2~24.04.1) |
| nlohmann json | 3.11.3, single header, commit 9cca280a, SHA-256 `9bea4c80…ea6` |
| Python | 3.12 (venv `http-custom-update`) |

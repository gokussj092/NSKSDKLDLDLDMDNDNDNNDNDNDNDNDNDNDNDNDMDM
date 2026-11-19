# REPRODUCE — TLS Tunnel 8.5.0 / 516 — OFFLINE

Todos los comandos se ejecutan desde la raíz del repo
(rama `offline/tls`, worktree `~/workspace/spdecode-offline-tls`).
Python de referencia: `~/workspace/http-custom-update/venv/bin/python`
(PyCryptodome 4.4.0). No se necesita Android SDK para el harness host.

## 1. Oráculo Python (servidor, ya en el repo)

```bash
# Suite del repo (6 sintéticas OK, 1 skipped: la muestra real es privada)
~/workspace/http-custom-update/venv/bin/python -m unittest tests.test_tls_decoder -v

# Decodificar un archivo concreto con el oráculo
~/workspace/http-custom-update/venv/bin/python decoders/Python/TLS.py <archivo.tls>
```

## 2. Regenerar los fixtures sintéticos

```bash
cd analysis/com.tlsvpn.tlstunnel/516
~/workspace/http-custom-update/venv/bin/python tools/make_fixtures.py
# Escribe tests/fixtures/*.tls, *.txt y fixtures.json (hashes SHA-256)
```

## 3. Tests del expediente (oráculo contra fixtures propios)

```bash
cd analysis/com.tlsvpn.tlstunnel/516
~/workspace/http-custom-update/venv/bin/python -m unittest tests.test_method -v
# Esperado: Ran 7 tests — OK
```

## 4. Harness host C++ (decodificador nativo exacto, sin NDK)

```bash
# Desde la raíz del repo:
bash analysis/com.tlsvpn.tlstunnel/516/tools/build_host_harness.sh
# Equivalente manual:
cmake -S analysis/com.tlsvpn.tlstunnel/516/tools/host_harness \
      -B /tmp/tls-harness-build -DCMAKE_BUILD_TYPE=Release
cmake --build /tmp/tls-harness-build -j
/tmp/tls-harness-build/tls_harness analysis/com.tlsvpn.tlstunnel/516/tests/fixtures/tls-profile1.tls
```

El build descarga una vez el tarball Mbed TLS 3.6.7 fijado (SHA-256 verificado
por CMake FetchContent); si existe `SPDECODE_MBEDTLS_ARCHIVE` apuntando a
una copia local, se usa esa (como hace CI). nlohmann/json 3.11.3 se toma del
paquete de sistema `nlohmann-json3-dev` cuando existe, o del git fijado
`9cca280a4d0ccf0c08f47a99aa71d1b0e52f8d03`.

## 5. Comparación C++ vs oráculo (perfil por perfil)

```bash
cd analysis/com.tlsvpn.tlstunnel/516
~/workspace/http-custom-update/venv/bin/python tools/run_harness.py
# Esperado: 13/13 MATCH; escribe RESULTS_harness.json junto a RESULTS.md
```

## 6. Verificación con una muestra real (pendiente)

Con un `.tls` real exportado por TLS Tunnel 8.5.0 o 8.5.2 (NO se guarda en
git; la muestra es privada):

```bash
~/workspace/http-custom-update/venv/bin/python decoders/Python/TLS.py <muestra.tls>
/tmp/tls-harness-build/tls_harness <muestra.tls>
# Ambas salidas deben coincidir (mismo JSON, mismo key_profile).
```

## 7. Compilación del APK offline (CI, no en esta VM)

La VM no tiene Android SDK. El APK offline se compila en CI desde la rama
`offline/tls` (o tras el merge que haga el coordinador), que ya incluye
`spdecode_tls_tunnel.cpp` en el target `offdecode` de
`android/app/src/main/cpp/CMakeLists.txt`.

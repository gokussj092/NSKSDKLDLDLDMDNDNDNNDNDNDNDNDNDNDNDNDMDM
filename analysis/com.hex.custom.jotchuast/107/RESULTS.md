# Hex Custom 10.6.7 — resultados

Estado: **PARTIAL** (FILE_ONLY; sin catálogo de proveedor; la nube es un
buzón de archivos por clave, no un catálogo).

## Verificado en esta entrega (2026-11-17)

- Self-test del decodificador nuevo en su ruta del repo:
  `Hex_Custom_10.6.7.py --self-test` → **11/11**.
- `tools/verify_107.py` (sintético, sin archivos reales): **5/5**
  (self-test 11/11, round-trip sin contraseña, round-trip con
  contraseña, contraseña incorrecta → WRONG_PASSWORD, sin contraseña →
  PASSWORD_REQUIRED, archivo manipulado rechazado).
- Rama con contraseña sin cambios: el decodificador nuevo abre la
  muestra 10.6.4 `NONE_BREAKER__0_0osx.hexcm` (7.054 B,
  SHA-256 `7babe831f18dbd9822eca9fbf50ee51cd361a71310776ef0197bf3d9d97aca32`)
  con **JSON idéntico** al decodificador 10.6.4.
- Rama sin contraseña por la ruta del worker (`hex_custom_bridge.py` +
  `engine.decode_file`): archivo real FastDNS
  (6.958 B, SHA-256
  `ea016cb4a609e609bb66202f0ba1b0f1d5fe6a0f94eba2982327643be2e53d49`)
  abre sin contraseña: perfil FastDNS, serverType 19,
  `test.hexapps.app:53`, empresa OXXO CEL, país mx.
- Bloqueo HWID como metadato: los 3 archivos `bait` abren por el bridge
  (solo contraseña; solo HWID sin contraseña; contraseña + HWID).
  SHAs y resumen en ANALYSIS.md; los archivos y los valores de
  contraseña/HWID NO se guardan en el repo.
- Descarga en la nube verificada en vivo (ver `CLOUD_DOWNLOAD.md`):
  Firestore `hexcustom-d3bc9`, colección `archivos`, documento
  `HexCustom-BoKo2Q5gQR` → HTTP 200; el contenido abre con la rama sin
  contraseña (mismo perfil FastDNS, re-exportado).
- `Hex_Custom_archivos.py` (10.6.4) intacto; `Hex_Custom.py` (catálogo)
  intacto; `file-formats.json` intacto.
- Icono `hex-custom.png` añadido (512×512, SHA-256
  `d4282f169624e8393fd5f50b9a8fff2377e9be05e1ddcdaffe6a9d9b620b532e`).
- Suites Python del método (`test_hex_custom_recovery`,
  `test_hx_tunnel`): **29/29 pass** (parte de la corrida conjunta de
  39 tests: 38 pass + 1 fallo pre-existente del pin 270, ver abajo).
- Suites Node relevantes: **82/82 pass**; suite Node completa: 874/881
  (3 fallos pre-existentes esperados + 1 flaky del broker DTunnel por
  contención en la corrida completa, que pasa aislado 6/6; ver
  INTEGRATION_TESTS.md).

## Fallos pre-existentes (no causados por este cambio)

- Pin de conteo de motores Cloud: `276 != 270` en
  `test_hex_tunnel`, `test_cloud_c8_vpn_registry` y
  `test_cloud_c8_worker_integration` (el repo lleva 276 motores tras la
  integración de 8 apps; los tests esperan 270). Verificado igual en el
  head limpio `d9adf97f`.
- Pin de inventario Python: `81 != 57` en
  `test_supplied_integrations` (el inventario lleva 81 apps; el test
  espera 57). Verificado igual en el head limpio `d9adf97f`.
- Node: `legal-monetization` 1 fallo + `store-terms` 2 fallos
  (pre-existentes según la integración anterior).

## Pendientes

1. Fórmula de la firma (`signature`, SHA-256 de 64 hex): sigue sin
   determinarse con las dos muestras disponibles. No hace falta para
   abrir el archivo. Al sellar se pone `SHA-256(JSON sin signature)` y
   se advierte; la app podría rechazar el archivo al importarlo si
   valida la firma.
2. Confirmación de extremo a extremo de un `.hexcm` sellado por el
   script (importarlo en la app en un teléfono, en ambas ramas).
3. Escritura en la nube no probada: solo se probó la lectura (GET).
   Subir un archivo (`reservarId`/`subirArchivo`) no se intentó para no
   escribir en el Firestore de otro.
4. Un segundo `.hexcm` con contraseña sellado por la app 10.6.7
   (para confirmar que la rama con contraseña no tiene ningún otro
   cambio sutil además de lo verificado con el archivo 10.6.4).

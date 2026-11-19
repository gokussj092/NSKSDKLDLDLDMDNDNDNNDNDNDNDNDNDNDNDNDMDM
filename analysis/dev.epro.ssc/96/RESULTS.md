# SSC Custom — resultados (dev.epro.ssc, 96)

Fecha: 2026-11-18. Entorno: VM Linux, venv python con PyCryptodome
4.4.0, g++ 13.3.0, nlohmann json 3.11.3 (pin de CMakeLists).

## Estado honesto: VERIFIED_SYNTHETIC

El decodificador offline está verificado por round-trip completo
contra el decodificador del servidor y contra el C++ nativo, pero
**solo con fixtures sintéticos**. No hay muestra real exportada por
SSC Custom 4.3.13. No es VERIFIED.

## 1. Oráculo Python vs decodificador del servidor — 24/24

`tools/verify.py` (2026-11-18), servidor
`~/workspace/spdecode-patch/decoders/Python/SSCCUSTOM.py`:

| Caso | Oráculo==esperado | Servidor==esperado | Oráculo==servidor |
| --- | --- | --- | --- |
| single_layer | PASS | PASS | PASS |
| two_layer | PASS | PASS | PASS |
| inner_encrypted | PASS | PASS | PASS |
| ssc_link | PASS | PASS | PASS |
| truncated | rechaza | rechaza | — |
| bad_hex | rechaza | rechaza | — |
| garbage | rechaza | rechaza | — |
| empty | rechaza | rechaza | — |
| odd_hex | rechaza | rechaza | — |
| valid_l1_no_json | rechaza | rechaza | — |

24 checks PASS, 0 FAIL. Los 4 positivos devuelven el JSON mapeado
completo; los 6 negativos devuelven `None` en ambos.

Hallazgos al ejecutar el servidor (no errores, quirks reproducidos):
- Dos capas: los perfiles quedan con claves de una letra
  (`{"e": ..., "l": ...}` dentro de `CONFIGS`).
- Campos internos L3 cortos (≤16 hex) quedan cifrados: en
  `inner_encrypted`, `DNS`/`PROXY`/`NSSERVER` salen como hex
  (`fff423207c7e4a`, `f6ea353e6a605c87`, `fef422207d7e4b`).
  Ver ANALYSIS.md §4.

## 2. Decodificador nativo C++ vs oráculo — 12/12

`tools/build_host_harness.sh` (2026-11-18), producción
`spdecode_ssc.cpp` sin cambios, `g++ -std=c++17 -O2 -Wall -Wextra
-Werror`, `json.hpp` fijado verificado por SHA-256:

| Caso | Resultado |
| --- | --- |
| single_layer | PASS (JSON idéntico campo por campo) |
| two_layer | PASS (incluye el quirk de claves de una letra) |
| inner_encrypted | PASS (incluye la guarda de longitud L3) |
| ssc_link | PASS |
| chacha20_kat | PASS (ChaCha20-64, contador 1, coincide con PyCryptodome) |
| chacha20_kat/not-a-file | PASS (los bytes KAT no son un .ssc válido) |
| truncated / bad_hex / garbage / empty / odd_hex / valid_l1_no_json | PASS (los 6 rechazan con excepción SSC_*) |

12 passed, 0 failed.

Defectos encontrados por el harness y corregidos en el acto:
- `keyMap` declarado con 26 entradas pero solo 25 definidas (falta
  `d`, como en el mapa Python): el elemento 26 quedaba en `nullptr` y
  `mappedKey` hacía segfault. Corregido a 25.
- Comparación con signo en `cleanJson` (`e.byte <= ...`).
- Función `toHex` sin uso (eliminada).
  La corrida con AddressSanitizer/UBSan localizó el segfault.

## 3. Tests del dossier — 3/3

`python3 analysis/dev.epro.ssc/96/tests/test_method.py -v`:
`Ran 3 tests ... OK` (oráculo vs servidor, harness nativo,
sanidad de los JSON esperados). No hay pytest en esta VM; el archivo
usa `unittest` de la stdlib (también compatible con pytest).

## 4. Integración offline (código, sin compilar APK aquí)

- `spdecode_ssc.{h,cpp}` nuevo; `CMakeLists.txt` lo añade a `offdecode`.
- `spdecode_offline_native.cpp`: formato `"ssc"` → `decodeSsc()` y
  prefijo `SSC_` en el catch de errores.
- `MainActivity.kt`: `"ssc"` en `supportedFiles`; `ssc://` → sufijo
  `"ssc"` en `beginText`.
- `OfflineUi.kt`: la lista del diálogo de importación ahora incluye
  `.ziv · .ssc` (`.ziv` ya estaba soportado pero no listado).
- **APK offline NO compilado en esta VM** (no hay Android SDK);
  corresponde a CI + prueba en teléfono de Pedro.

## 5. Lo que falta para VERIFIED

Un `.ssc` real exportado por SSC Custom 4.3.13 (versionCode 96) o un
enlace `ssc://` real. Con él: correr `verify.py` + harness con el
archivo real (sin guardarlo en git) y confirmar que abre. Sin él, el
estado se queda en VERIFIED_SYNTHETIC. Tampoco se pudo descargar el
APK (APKPure 403, APKCombo HTML, APKMirror sin conexión), así que no
hay lista de librerías nativas por split ni confirmación de que 4.3.13
mantenga el sobre L1/L2: solo un archivo real lo confirma.

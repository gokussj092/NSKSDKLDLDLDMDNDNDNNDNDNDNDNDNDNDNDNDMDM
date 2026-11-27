# Dossier 942 — port n19 al decoder C++ offline (staging, sin merge)

Adaptado para el port C++ offline desde el expediente de la nube.
Estado: **PARTIAL** (ver RESULTS.md). Nada de aquí está pusheado; el
`.cpp.new` vive en `~/workspace/offline-hc942/staging/`.

## Contenido

- `MANIFEST.json`, `ANALYSIS.md`, `REPRODUCE.md`, `RESULTS.md`,
  `RESULTS_harness.json`, `DEPENDENCIES.md` — expediente adaptado
  (code_paths al C++ offline; verificación pendiente de confirmar por el
  verificador).
- `tools/make_synthetic_n19.py` — builder de fixtures sintéticos n19/n15
  + 12 checks (C++ vs oráculo Python, rama protegida, HPR1, V4, tamper,
  regresión n15).
- `tools/run_real_checks.py` — checks sobre los archivos reales del
  propietario (se leen en runtime desde su ruta privada; no se guardan
  bytes ni contenido descifrado).
- `tools/ref_oracle/` — copias de solo lectura del oráculo Python
  (`codec.py`, `crypto.py`, `_hc_hccfg.py`).
- `tests/test_hc_n19.py` + `tests/fixtures/` — 8 unit tests y 3 fixtures
  sintéticos (n19 abierto, n19 protegido, n15 abierto).
- `cloud-src/` — expediente de la nube 942 íntegro, fetchado de
  ci/unity-ads-online-qa (solo lectura, procedencia en MANIFEST.json).
- `offline934-ref/` — expediente offline 934 (rama
  feat/version-offline-apk), usado como precedente estructural.
- `cloud-src-README.md` — README del paquete en la nube (referencia).

## Lo que NO hay aquí

- Ni el `.cpp.new` (está en `~/workspace/offline-hc942/staging/
  spdecode_http_custom.cpp.new`), ni muestras reales, ni contraseñas, ni
  contenido descifrado, ni nombres reales.

# Pruebas de integración — Hex Custom 10.6.7

## Propias (dossier)

- `tools/verify_107.py` — 5/5 pass (self-test 11/11, round-trip sin
  contraseña, round-trip con contraseña, WRONG_PASSWORD,
  PASSWORD_REQUIRED, archivo manipulado rechazado). Sintético, sin
  archivos reales, sin red.
- Verificación con archivos reales por ruta privada (ver RESULTS.md):
  NONE_BREAKER 10.6.4 (JSON idéntico entre decodificadores), FastDNS
  sin contraseña por bridge y por `engine.decode_file`, 3 archivos
  `bait` por el bridge (solo contraseña, solo HWID, contraseña + HWID).

## Reutilizadas (repo)

- `tests/test_hex_custom_recovery.py` + `tests/test_hx_tunnel.py` —
  29/29 pass.
- `python3 scripts/cloud_formats_catalog.py` (sin `--write`):
  "Public Cloud format catalogue matches all currently registered file engines."
- Suites Node `supplied-integrations`, `server-vpn-catalog`,
  `file-formats`, `text-format-catalog`, `catalog-icons`,
  `catalog-snapshots`, `server-vpn-version-sync`, `c12-provider-controls`:
  82/82 pass. Suite Node completa: 874/881 — 3 fallos pre-existentes
  (`legal-monetization` 1, `store-terms` 2) + 1 flaky del broker DTunnel
  en la corrida completa por contención de recursos (el worker aislado
  muere con código null tras 15 s); el mismo test pasa aislado 6/6 en
  esta rama y en el head limpio `d9adf97f`, y pasó en la corrida parcial
  de 8 suites (5,8 s).

## Fallos pre-existentes (no causados por este cambio)

- `276 != 270` (pin de motores Cloud) en `test_hex_tunnel`,
  `test_cloud_c8_vpn_registry`, `test_cloud_c8_worker_integration`.
- `81 != 57` (pin de inventario) en `test_supplied_integrations`.
  Ambos verificados iguales en el head limpio `d9adf97f`.

## No probado (pendiente)

- Importación en teléfono de un `.hexcm` sellado por el script.
- Escritura en la nube (solo se probó la lectura).
- Segundo `.hexcm` con contraseña sellado por la app 10.6.7.

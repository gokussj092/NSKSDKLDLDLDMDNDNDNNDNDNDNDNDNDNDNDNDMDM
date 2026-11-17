# Pruebas de integración — HexVPN 1.7.3-Rev

## Reutilizadas (repo)

- `tests/test_hex_tunnel.py` — 9/10 pass. El único fallo es el pin
  desactualizado del conteo de motores Cloud (270 esperado, 276 real),
  pre-existente en el head `d9adf97f`, ajeno a esta integración.
- `python3 scripts/cloud_formats_catalog.py` (sin `--write`):
  "Public Cloud format catalogue matches all currently registered file engines."
- Suites Node `supplied-integrations`, `server-vpn-catalog`,
  `file-formats`, `text-format-catalog`, `catalog-icons`,
  `catalog-snapshots`, `server-vpn-version-sync`, `c12-provider-controls`:
  82/82 pass.

## Propias (dossier)

- `tests/test_live_json.py` — 2/2 pass: esquema del `live.json`
  guardado (NO_CATALOG, 27 sondas 401, 0 servidores) y ausencia de
  APIs de descarga o secretos.
- `tools/HexVPN.py --probe` — re-sondeo en vivo 2026-11-17 22:54 UTC:
  27/27 HTTP 401, 0 servidores.

## No probado (pendiente)

- `.hexcm` real exportado por ESTE build (1.7.3-Rev) en un teléfono.
- Variante doble con muestra real (solo sintética).
- Catálogo en vivo (no hay endpoint recuperable; solo queda la captura
  de red en un teléfono).

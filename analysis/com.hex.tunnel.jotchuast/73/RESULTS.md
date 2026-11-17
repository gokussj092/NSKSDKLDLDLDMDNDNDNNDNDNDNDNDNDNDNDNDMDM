# HexVPN 1.7.3-Rev — resultados

Estado: **PARTIAL** (FILE_ONLY; sin catálogo en vivo).

## Verificado en esta entrega (2026-11-17)

- Decodificador del repo byte-idéntico al entregado:
  `decoders/Python/apps/Hex_Tunnel/file_decoder.py`
  SHA-256 `9bb9958199b3e3695ffc8a0003621837a95dbee3f5b10f0d086fd0539d265e68`
  = `HexVPN_archivos.py` del lote. No se modificó.
- `python3 -m unittest tests.test_hex_tunnel -v`: **9/10 pass**.
  Los 9 cubren 12 documentos válidos simples y dobles contra vectores
  dorados, 10 rechazos, truncado/corrupción, CLI fuera del checkout y
  ruta del worker. El único fallo es el pin de conteo del registro
  Cloud en `test_cloud_catalog_is_file_only_and_c0_is_unchanged`
  (espera 270 motores, el repo lleva 276 tras la integración de 8 apps
  del 2026-11-17): **fallo pre-existente, ajeno a este cambio**
  (verificado igual en el head limpio `d9adf97f`).
- `test_hexvpn.py` del lote: 6/7; el único fallo es
  `test_live_json_schema` porque el `live.json` entregado venía resumido
  (sin el array `probes`). Re-sondeo en vivo el 2026-11-17 22:54 UTC con
  `HexVPN.py --probe`: **27/27 HTTP 401, 0 servidores, NO_CATALOG**
  (el `live.json` completo con las 27 sondas se guarda en este dossier).
- Entrada supplied `hex-tunnel` (FILE_ONLY, `requests: []`) + icono
  `hexvpn.png` 512×512 (SHA-256
  `26c75e7b0f2e878aa0d41c8cc6e6128f4badfd047c991def617f17785a31db71`).
- `python3 scripts/cloud_formats_catalog.py` (sin `--write`):
  "Public Cloud format catalogue matches all currently registered file engines."
- Suites Node relevantes (`supplied-integrations`, `server-vpn-catalog`,
  `file-formats`, `text-format-catalog`, `catalog-icons`,
  `catalog-snapshots`, `server-vpn-version-sync`, `c12-provider-controls`):
  **82/82 pass** (ver RESULTS global de la integración en el dossier 107).

## Pendientes

1. Captura de red en un teléfono durante "buscar actualizaciones":
   revelaría `updatesJsonUrl`/`serversUpdateUrl`, método, headers y
   User-Agent reales, y con eso el catálogo en vivo. Es el único camino
   que queda para el catálogo.
2. Un `.hexcm` real exportado por este build en un teléfono:
   reconfirmación de extremo a extremo del lector (y si es de variante
   doble, primera muestra real doble).
3. Un archivo `.hex` real (si la app exporta con esa extensión).
4. Revertir el ISA de la VM KovSec para leer `AppConfig` sin teléfono:
   trabajo grande, sin garantía de éxito.

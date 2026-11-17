# STR VIP Proxy 1.42.5 — RESULTS

Fecha de verificación: 2026-11-17. Entorno: Python 3.12.3 del sistema.

## Estado por vía

- **catalog**: VERIFIED — v1.0.31 en vivo abre; 1.888/1.888 valores `enc:`
  descifran, 0 fallos. PERO la descarga en vivo no es expresable en
  `supplied-integrations.json` `requests[]` (App-Proof HMAC sin camino
  en el servidor); el cableado del catálogo queda pendiente de decisión.
- **files**: VERIFIED_SYNTHETIC — `.isc`: self-test 12/12; falta uno
  REAL exportado.
- **text**: VERIFIED_SYNTHETIC — `isv-config://` sintético (ruta real de
  la app); código `ISV-` solo verificado el 404; enlace WireGuard exacto
  sin confirmar.
- **export**: PENDING — sin código de nube `ISV-` real.

## Catálogo en vivo (re-corrida 2026-11-17 ~20:58 Tijuana)

Descarga con el script entregado contra el endpoint real:

- `--url --summary`: `catalog_version 1.0.31, servers 21, tweaks 686`
  (4,54 s; el primer intento de la tanda tardó 8,70 s por los reintentos
  de truncado + fallback curl).
- `--url -o /tmp/str_full.json` (367.388 B): **byte por byte idéntico**
  al `live.json` entregado (SHA-256
  `ed3cd7622e725cca1ab11d543bc1f87758a1927155e642b360e922d479add6c1`).
- `run()` offline sobre la respuesta guardada
  (`work/live_full.bin`, 487.493 B, SHA-256
  `e458db11c5364c1e906448616e23fb168e05ce91560cfcd4d8e00c2ddb250b3c`):
  1,53 s, salida idéntica al `live.json` (tope del worker: 20 s).
- `live.json`: 0 ocurrencias de `enc:`, sin APIs de descarga
  (sin `api/app`, sin `isvsoft.workers`).

## Self-tests del script operativo

- `STR_VIP_Proxy_archivos.py --self-test`: **12/12** (JSON `.isc`
  plano, enlace `isv-config://` cifrado, blob `enc:` suelto, base64
  tras `isv-config://`, `.ovpn`, enlaces vmess/vless/trojan/ss, texto
  WireGuard, código `ISV-` marcador, token manipulado rechazado).
- `py_compile` de ambos scripts: OK (sistema y copias del staging).
- `run(b"not json")` y `run(b"garbage")` (ambos scripts): `None`.

## Tests del expediente

`python3 -m unittest discover -s tests -v` — ver salida en la entrega.
Fixture sintético (`tests/fixtures/synthetic_catalog.json`, host
`198.51.100.1` de TEST-NET y `test-payload`); un fixture sintético
demuestra la lógica implementada, NO prueba compatibilidad con una
versión real ni conectividad remota. La compatibilidad real la prueba
la re-corrida en vivo byte por byte de arriba.

## Qué se probó con oráculo independiente

- AES-256-GCM en Python puro verificado contra la librería nativa
  emulada (Unicorn) y contra `cryptography` en 1.951 valores `enc:`.
- Firma HMAC-SHA256 verificada contra `nativeSignProof` emulada en
  4 vectores y contra el servidor en vivo (403 sin ella / con query).
- Descargas en vivo verificadas dos veces (entrega original + re-corrida
  de esta tarea) con comparación byte por byte.

## Clasificación de evidencia

- `VERIFIED`: descarga en vivo verificada o archivo real abierto.
- `VERIFIED_SYNTHETIC`: solo muestra sintética sellada con el mismo método.
- `PARTIAL`: vía que abre pero con valores que no descifran o pasos pendientes.
- `PENDING` / `REQUIRES_DEVICE`: falta muestra real de teléfono o
  dispositivo registrado.
- `NOT_AUTHORIZED`: no aplica en este expediente (nada requirió sortear
  autenticación ajena).

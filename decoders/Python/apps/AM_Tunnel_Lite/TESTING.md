# AM Tunnel Lite — pruebas

## Python

```bash
cd ~/workspace/spdecode-patch
~/workspace/http-custom-update/venv/bin/python -m unittest tests.test_amtunnel -v
```

`tests/test_amtunnel.py` sigue el patrón de `tests/test_rmptunnel_lite.py`
y adapta el test del dossier (`analysis/app.vpn.amtunnellite/63/tests/`):

1. Round-trip XXTEA sobre un JSON sintético (`codec.xxtea_encrypt` →
   `codec.xxtea_decrypt`) y vector sintético conocido
   (`tests/golden/amtunnel_catalog_vectors.json`, Version `9.9`, 1 servidor
   / 1 payload, IPs TEST-NET-1) por `codec.decode_catalog_b64`,
   `server_catalog_decoder.run`, el worker aislado
   (`decode_provider_catalog('am-tunnel-lite', raw)`, `isPartial:false`) y
   el CLI `server_catalog_decoder.py --stdin` fuera del repo.
2. Negativas: delta estándar `0x9E3779B9` no abre el vector; blob corrupto
   (palabra de longitud inválida); respuesta HTML / no-Base64; entrada
   vacía y tamaño excesivo; `_NoRedirect` rechaza redirecciones.
3. `sanitize_catalog` redacta credenciales e IPs y conserva estructura y
   conteos (sobre el fixture sintético).
4. Ruta de archivos: `file_decoder.run` abre un `pdrv2.json` sintético y
   `engine.decode_file("pdtv2", raw)` lo sirve extremo a extremo;
   `file_decoder.parse_wg_conf` abre un `.conf` sintético válido y rechaza
   Endpoint no-IPv4, Hash corto y clave extra.
5. Los dos scripts entregables pasan su propio `--self-test`
   (`codec.py` 5/5, `file_decoder.py` 6/6).

`py_compile` de los tres scripts nuevos del módulo.

## Node

```bash
cd cloud/web && npm test -- tests/amtunnel-remote.test.mjs
```

`tests/amtunnel-remote.test.mjs` (modelo `pmtunnel-remote.test.mjs`,
fixture sintética en `tests/golden/amtunnel_catalog_vectors.json`):
descarga mock por rangos (206 + `Content-Range`, UA Android exacta, ruta
exacta `/updater/8112011e98856d3ca814d0f8ce3231`, sin redirecciones),
reintento de un rango abortado, rechazo de DNS privado, gateway
autenticado hacia el worker, y rechazo de resultados de worker
incompletos (rama propia `Free_servers`/`Payloads` de `c3-gateway.mjs`).
La versión del catálogo público es **96** (bump 95→96 aplicado por el
coordinador al ensamblar).

## En vivo (re-verificado 2026-11-22 durante la integración)

| Fuente | Bytes | Versión | Libres | Payloads | SHA-256 |
| --- | ---: | --- | ---: | ---: | --- |
| Catálogo en vivo (módulo ensamblado, `server_catalog_decoder.py --download`) | 163 960 | 4.6 | 172 | 137 | `38cca537…49da` (byte-idéntico al dossier) |
| Catálogo en vivo (worker aislado `decode_provider_catalog`, `isPartial:false`) | 163 960 | 4.6 | 172 | 137 | mismo blob |
| `pdrv2.json` embebido real (`file_decoder` + `engine.decode_file("pdtv2", …)`) | 156 216 | 1.5 | 165 | 128 | `3afd30a1…c688d3` |
| Catálogo en vivo (CLI `--stdin` sobre el blob guardado) | 163 960 | 4.6 | 172 | 137 | mismo blob |

Descarga en vivo del módulo ensamblado: **9,8 s** (por rangos, reintentos
incluidos; el dossier observó 11–18 s). Endpoints totales: **3.341**.
Premium / VIP / privados: **0 / 0 / 0**.

El catálogo en vivo pasa además por el worker aislado
`engine.decode_provider_catalog` con `isPartial: false`. El blob crudo
de referencia del dossier (2026-11-22) es: **163.960 B, Version 4.6,
172 servidores libres (3.341 endpoints), 137 payloads,
SHA-256 `38cca53786aa61f5842202b649b8e8a3bdff7aa6fa03ce9a34d387f2b31d49da`**.

**Límite del entorno de pruebas (no del patch):** el broker Node en vivo
(`downloadVpnCatalog("am-tunnel-lite")`) no se puede ejercer desde esta VM:
su DNS devuelve direcciones CGNAT `198.18.x.x` para todos los hosts y
`vettedIpv4` las rechaza con `REMOTE_NETWORK_DENIED` — el proveedor ya
integrado `pm-tunnel-lite` falla en vivo exactamente igual en esta VM.
La lógica de rangos del broker está probada con mocks (206 +
`Content-Range`, reintento de rango abortado) en
`tests/amtunnel-remote.test.mjs` y con sondas Node directas (206 por
rango, ~1 s por rango); la descarga completa por rangos está probada en
vivo en Python con el mismo algoritmo (9,8 s, blob byte-idéntico). En el
VPS, con DNS público real, el broker resuelve la IP pública y descarga
igual.

## Pendiente (no cubierto aquí)

- Muestra `pdrv2.json` real exportada del teléfono de Pedro (estado
  actual: el embebido real Version 1.5 sí abre; la ruta es
  `VERIFIED_REAL` por el catálogo remoto + embebido, no por exportación
  de usuario — la app no tiene importación por el usuario).
- Confirmación extremo a extremo en un dispositivo (la app carga el
  catálogo Version 4.6 y conecta a un servidor listado).
- Codificación de campo del token de cuenta superior (`Username` ==
  `Password`, 16 B) sin recuperar; no afecta al listado.
- Prueba en VPS tras el despliegue autorizado (`update all`).
- Decidir con Pedro si se retira la ficha antigua `am-tunnel-lite-vpn`
  (`remote:null`), distinta del proveedor nuevo `am-tunnel-lite`.

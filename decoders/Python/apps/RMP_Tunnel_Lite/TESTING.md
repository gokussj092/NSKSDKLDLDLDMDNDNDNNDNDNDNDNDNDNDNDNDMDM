# Comprobación puntual — RMP TUNNEL LITE RMP-4

Fecha: **2026-11-22**. Autorización expresa del usuario para catálogos externos.
Dossier completo en `analysis/com.rmptunnel.lite/4/` (ANALYSIS.md, RESULTS.md,
REPRODUCE.md, MANIFEST.json, DEPENDENCIES.md, tools/, tests/ con fixtures
sanitizados) — local, no va en el patch.

## Python

```bash
cd ~/workspace/spdecode-patch
~/workspace/http-custom-update/venv/bin/python -m unittest tests.test_rmptunnel_lite -v
```

`tests/test_rmptunnel_lite.py` sigue el patrón de `tests/test_rmp_tunnel_pro.py`
y añade la ruta de archivos/textos del patrón NetFlux:

1. Vector completo del motor compartido (`tests/golden/mx_tunnel_pro_vectors.json`,
   generado de forma independiente con el oráculo JDK) a través de
   `codec.decode_catalog` + `render`, del worker aislado
   (`decode_provider_catalog('rmp-tunnel-lite', raw)`, `isPartial:false`) y
   del CLI `server_catalog_decoder.py --stdin` fuera del repo.
2. Rechazo de entrada vacía, HTML, Base64 truncado, longitud truncada,
   tamaño excesivo, vectores inválidos del golden y redirecciones.
3. Round-trip sintético `.rmplite` (helper de cifrado local en el propio test,
   inverso del descifrado; misma receta verificada con el oráculo nativo
   Unicorn): `file_decoder.run`, enlace `rmplite://`, marcador opcional
   `RMPLITE`, esquema en mayúsculas y ruta C8 del worker
   (`engine.decode_file("rmplite", raw)`).
4. Enlace `rmplite://` extremo a extremo por `text_bridge.dispatch`.
5. Rechazos: texto plano, hex inválido, enlace no-rmplite, basura tras
   descifrar y payload vacío.

`py_compile` de los tres scripts nuevos del módulo.

## Node

```bash
cd cloud/web && npm test -- tests/rmptunnel-lite-remote.test.mjs
```

`tests/rmptunnel-lite-remote.test.mjs` (modelo `gcpvpn-remote.test.mjs`,
fixture sintética compartida en `tests/golden/mx_tunnel_pro_vectors.json` —
el motor es el mismo que PRO, no se crea un golden nuevo): descarga mock
con DNS validado y TLS en la ruta exacta `.../RMPLITE`, rechazo de
redirecciones y de DNS privado, gateway autenticado hacia el worker, y
rechazo de resultados de worker incompletos (rama Free_servers/Payloads
de `c3-gateway.mjs`). La versión del catálogo público es **95** (bump
94→95 aplicado por el coordinador al ensamblar el lote).

## En vivo (re-verificado 2026-11-22 durante la integración)

| Fuente | Bytes | Versión | Libres | Payloads | SHA-256 |
| --- | ---: | --- | ---: | ---: | --- |
| RMPLITE en vivo (lote 16) | 723 808 | 10.3 | 40 | 1255 | `a977755b…b99b0` |
| RMPLITE en vivo (re-verificación) | 723 984 | 10.4 | 40 | 1255 | `8f61ee74…eb55d` |
| RMPPRO en vivo (mismo momento) | 723 984 | 10.4 | 40 | 1255 | `8f61ee74…eb55d` (idéntico) |
| Asset `gremlin.json` | 698 936 | 3.8 | 40 | 1211 | `03c9cc0f…501` |

El catálogo en vivo decodifica con el motor compartido ya integrado; el
cambio 10.3→10.4 es solo de versión, los conteos no se mueven. No se guardan
en Git catálogos reales, valores descifrados ni credenciales.

## Pendiente (no cubierto aquí)

- Muestra `.rmplite` real o enlace `rmplite://` real del teléfono de
  Pedro (estado actual: `VERIFIED_SYNTHETIC`).
- `server.psi`: alineación nativa sin resolver (PARTIAL, sin decoder).
- Prueba en VPS tras el despliegue autorizado (`update all`).

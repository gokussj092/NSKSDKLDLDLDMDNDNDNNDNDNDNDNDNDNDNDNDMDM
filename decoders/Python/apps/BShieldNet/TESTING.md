# B SHIELD NET — pruebas

## Python

```bash
cd <repo>
<venv>/bin/python -m pytest tests/test_bshieldnet.py -v
<venv>/bin/python -m pytest tests/test_bshieldnet_file_text.py -v   # (si existe, entregable)
```

`tests/test_bshieldnet.py` construye fixtures sintéticos con el
generador inverso de `bshieldnet.py` (`encrypt_profile`, verificado
byte-idéntico contra el blob vivo) y comprueba:

1. `codec.decode_catalog` + `render` devuelven el documento
   descifrado esperado (Version 7.34, 1 servidor, 1 network).
2. `decode_provider_catalog('bshield-net', raw)` por el worker
   aislado entrega el mismo documento (`isPartial:false`).
3. El CLI `server_catalog_decoder.py --stdin` fuera del repo
   entrega el mismo documento.
4. El fixture dorado comprometido
   (`tests/golden/bshieldnet_catalog_vectors.json`, valores
   sintéticos) abre por `catalog.run` al documento esperado.
5. El resultado NO contiene la URL de descarga del catálogo ni
   rutas de scripts (`raw.githubusercontent.com/snapb`,
   `decoders/Python/`, `"script":`, `source_script`).
6. Round-trip de archivo `.bshield` y de enlaces `bshieldnet://`
   / `bshield://` por `file_decoder` y por las rutas canónicas
   (`decode_file('bshield', …)` del motor y
   `text_bridge.dispatch`); truncado, basura, esquema
   equivocado y perfil equivocado se rechazan.
7. Rechazo de entrada vacía, HTML, catálogo truncado, `Servers`
   / `Networks` ausentes o vacíos, JSON duplicado y perfil
   `7net` (mismo sobre, otra clave).

El self-test del entregable (`bshieldnet.py --self-test`,
round-trip 8/8) sigue pasando sin cambios. Regresión existente:
las suites RENZ vecinas (`tests/test_renz_family.py`,
`tests/test_netfluxvpn.py`, `tests/test_gcpvpn.py`) no se tocan.

## Node

```bash
cd cloud/web && npm test -- tests/bshieldnet-remote.test.mjs
```

`tests/bshieldnet-remote.test.mjs` (modelo
`netfluxvpn-remote.test.mjs`, fixture sintética en
`tests/golden/bshieldnet_catalog_vectors.json`): descarga mock con
DNS validado y TLS en la ruta exacta de GitHub raw, rechazo de
redirecciones y de DNS privado, gateway autenticado hacia el
worker, y rechazo de resultados de worker incompletos (sin
`Servers`, sin `Networks`, `kind` distinto, otro proveedor,
`isPartial:true`). La versión del catálogo público es **99**
(pendiente del bump del coordinador 98 → 99).

## Pendiente (no cubierto aquí)

- Un `.bshield` real exportado por la app para cerrar archivos
  como `VERIFIED_REAL` (hoy `VERIFIED_SYNTHETIC`).
- Un enlace `bshieldnet://` (o `bshield://`) real para cerrar
  textos como `VERIFIED_REAL` (hoy `VERIFIED_SYNTHETIC`).
- Prueba en VPS tras el despliegue autorizado (`update all`).

# MAYA TUN PRO — pruebas

## Python

```bash
cd ~/workspace/spdecode-patch
~/workspace/http-custom-update/venv/bin/python -m unittest tests.test_mayatun -v
```

`tests/test_mayatun.py` construye fixtures sintéticos con los
generadores inversos locales (XTS para el sobre exterior, GCM para los
campos de servidor, CBC para los campos de Tweaks, ChaCha20-Poly1305
para el enlace `maya://`) y comprueba:

1. `codec.decode_catalog` + `render` devuelven el documento esperado.
2. `decode_provider_catalog('maya-tun-pro', raw)` por el worker aislado
   entrega el mismo documento (`isPartial:false`).
3. El CLI `server_catalog_decoder.py --stdin` fuera del repo entrega
   el mismo documento.
4. El fixture dorado comprometido
   (`tests/golden/mayatun_catalog_vectors.json`, valores sintéticos con
   nonces/tweaks/IV fijos) abre por `codec.run` al documento esperado.
5. La ruta de archivos existente: un `.maya` sintético (sobre CBC +
   GCM interno, esquema del repo) abre por `decoders/Python/maya.py`
   (`run` + `decrypt_profile`).
6. Round-trip de enlace `maya://`: un `.maya` sintético cifrado con
   ChaCha20-Poly1305 (modo 3) abre por `codec.decode_text` y por el
   despacho real de `text_bridge.dispatch`.
7. Rechazo de entrada vacía, HTML, sobre truncado, clave XTS
   equivocada, campo `Servers` ausente y campo `Tweaks` ausente; un
   enlace `maya://` manipulado o con otra clave devuelve `None`.

Regresión NoobCrypt existente (antes y después de esta entrega):

```bash
~/workspace/http-custom-update/venv/bin/python -m unittest \
  tests.test_cloud_c2_text -v
```

## Node

```bash
cd cloud/web && npm test -- tests/mayatun-remote.test.mjs
```

`tests/mayatun-remote.test.mjs` (modelo
`gcpvpn-remote.test.mjs`, fixture sintética en
`tests/golden/mayatun_catalog_vectors.json`): descarga mock con DNS
validado y TLS, rechazo de redirecciones y de DNS privado, gateway
autenticado hacia el worker, y rechazo de resultados de worker
incompletos (sin `Tweaks`, `kind` distinto, otro proveedor,
`isPartial:true`). La versión del catálogo público es **95**.

## Pendiente (no cubierto aquí)

- Muestra `.maya` real o enlace `maya://` real del teléfono de
  Pedro (estado actual: `VERIFIED_STATIC` archivos,
  `VERIFIED_SYNTHETIC` texto).
- Prueba en VPS tras el despliegue autorizado (`update all`).

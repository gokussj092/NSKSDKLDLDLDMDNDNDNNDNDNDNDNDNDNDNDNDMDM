# HTTP WinzapVPN — pruebas

## Python

```bash
cd ~/workspace/spdecode-patch
~/workspace/http-custom-update/venv/bin/python -m unittest tests.test_winzapvpn -v
```

`tests/test_winzapvpn.py` construye fixtures sintéticos con los
generadores inversos locales (bootstrap JSON con sesión/anuncios/
tokens que el codec debe recortar, blob `Winzap01` + capa 3 con
`encode_winzap01_blob`/`encode_field`) y comprueba:

1. `codec.decode_catalog` + `render` devuelven el documento redactado
   esperado (sin `session`, sin `ad_controls`, sin `home_background`,
   sin `change_token`, sin la lista plana `servers`).
2. `decode_provider_catalog('winzap-vpn', raw)` por el worker aislado
   entrega el mismo documento (`isPartial:false`).
3. El CLI `server_catalog_decoder.py --stdin` fuera del repo entrega
   el mismo documento.
4. El fixture dorado comprometido
   (`tests/golden/winzapvpn_catalog_vectors.json`, valores sintéticos
   con salt/IV fijos) abre por `codec.run` al documento esperado.
5. Round-trip del blob `Winzap01`: un blob sintético con campos de
   capa 3 abre por `codec.decode_winzap01_blob` con claves largas;
   header inválido, cuerpo no múltiplo de 16 y campo de capa 3
   corrupto se rechazan o se dejan como están, como hace la app.
6. Rechazo de entrada vacía, HTML, JSON duplicado, `config_version`
   ausente, `countries` vacío y servidor sin `id`/`name`.

Regresión existente (antes y después de esta entrega): no hay suite
previa de Winzap; las suites de catálogo vecinas (`tests.test_mayatun`,
`tests.test_pmtunnel`) no se tocan.

## Node

```bash
cd cloud/web && npm test -- tests/winzapvpn-remote.test.mjs
```

`tests/winzapvpn-remote.test.mjs` (modelo
`mayatun-remote.test.mjs`, fixture sintética en
`tests/golden/winzapvpn_catalog_vectors.json`): descarga mock con DNS
validado y TLS en el puerto fijo 2083 con el `device_id` exacto,
rechazo de redirecciones y de DNS privado, gateway autenticado hacia
el worker, y rechazo de resultados de worker incompletos (sin
`countries`, sin servidores, `kind` distinto, otro proveedor,
`isPartial:true`). La versión del catálogo público es **98**.

## Pendiente (no cubierto aquí)

- Blob `Winzap01` real (`encrypted_mobile_config` de un perfil) para
  cerrar el blob como `VERIFIED_REAL` (hoy `VERIFIED_SYNTHETIC`).
- Cabeceras firmadas válidas de una sesión real de la app para
  descargar perfiles por servidor (el HMAC no se reproduce ni se
  falsifica); el catálogo completo de configuraciones queda PENDING.
- Build 1.1.62 anunciado por el servidor (`latest_version`): sin
  analizar; no se afirma compatibilidad.
- Prueba en VPS tras el despliegue autorizado (`update all`).

# Ways Tunnel — pruebas

## Python

```bash
cd <repo-root>
~/workspace/http-custom-update/venv/bin/python -m unittest tests.test_waystunnel -v
~/workspace/http-custom-update/venv/bin/python decoders/Python/apps/Ways_Tunnel/waystunnel.py --self-test
```

`tests/test_waystunnel.py` construye fixtures sintéticos con los
generadores inversos locales (catálogo con campos de credenciales y
enlace de invitación que el codec debe recortar, tweak `wyst://`
con `encrypt_tweak`) y comprueba:

1. `server_catalog_decoder.decode_catalog` + `render` devuelven el
   documento redactado esperado (sin `WhatsApp`, sin `ServerIP` /
   `ServerUser` / `ServerPass` / `ProxyIP` / `SlowChave` /
   `TokenAuth` / `NameServer` / `udpserver` / `udpobfs` /
   `udpauth` / `OpenVPNConfig` / `v2rayJson`, sin `SlowDns` en
   networks, sin la API de descarga).
2. `decode_provider_catalog('ways-tunnel', raw)` por el worker
   aislado entrega el mismo documento (`isPartial:false`).
3. El CLI `server_catalog_decoder.py --stdin` fuera del repo entrega
   el mismo documento.
4. El fixture dorado comprometido
   (`tests/golden/waystunnel_catalog_vectors.json`, valores sintéticos
   con glifos deterministas) abre por `server_catalog_decoder.run`
   al documento esperado.
5. Round-trip del tweak `wyst://`: un tweak sintético abre por
   `text_decoder.decode_text` al documento esperado; esquema ajeno
   → `None`; tweak corrupto → `None`; tweak con contraseña →
   `CREDENTIALS_NOT_ALLOWED`.
6. Rechazo de entrada vacía, HTML, glifos con longitud impar, glifo
   fuera del alfabeto, `Version` ausente, `Servers` vacío,
   `Networks` vacío y servidor sin `Name`.
7. El catálogo vivo real (NO corre por defecto; nunca se guarda en
   el repo): `WAYS_REAL_CATALOG=<glifos>` o `--download` contra el
   endpoint fijo; debe dar v1.0.49, 5 servidores, 78 networks y el
   documento redactado debe coincidir con
   `~/workspace/catalogs/waystunnel/catalog.json` salvo
   `ReleaseNotes` si cambia.

Regresión existente (antes y después de esta entrega): no hay suite
previa de Ways; las suites de catálogo vecinas
(`tests.test_winzapvpn`, `tests.test_mayatun`) no se tocan.

## Node

```bash
cd cloud/web && npm test -- tests/waystunnel-remote.test.mjs
```

`tests/waystunnel-remote.test.mjs` (modelo
`winzapvpn-remote.test.mjs`, fixture sintética en
`tests/golden/waystunnel_catalog_vectors.json`): descarga mock con
DNS validado y TLS en el host fijo `raw.githubusercontent.com` con
la ruta exacta `/waystunnel/politicas/refs/heads/main/config.json`,
rechazo de redirecciones y de DNS privado, gateway autenticado
hacia el worker, y rechazo de resultados de worker incompletos (sin
`Version`, sin servidores, sin networks, `kind` distinto, otro
proveedor, `isPartial:true`). La versión del catálogo público es
**99** (la sube el coordinador).

## Pendiente (no cubierto aquí)

- Tweak `wyst://` real para cerrar el tweak como `VERIFIED_REAL`
  (hoy `VERIFIED_SYNTHETIC`).
- Muestras `vmess://` / `vless://` en claro (hoy solo inferidas).
- Prueba en VPS tras el despliegue autorizado (`update all`).

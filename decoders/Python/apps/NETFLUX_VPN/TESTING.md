# NetFlux VPN — pruebas

## Python

```bash
cd ~/workspace/spdecode-patch
~/workspace/http-custom-update/venv/bin/python -m unittest tests.test_netfluxvpn -v
```

`tests/test_netfluxvpn.py` construye un catálogo sintético completo con
los generadores inversos de `tests/test_renz_family.py`
(`profile_fixture` para el sobre exterior, `special_fixture` para un
host, un sobre sensible PBKDF2-XXTEA-AES para credenciales y un sobre
principal para `SlowDNS.PubKey` con su valor hex de 64 caracteres) y
comprueba:

1. `codec.decode_catalog` + `render` devuelven el documento esperado.
2. `decode_provider_catalog('netflux-vpn', raw)` por el worker aislado
   entrega el mismo documento (`isPartial:false`).
3. El CLI `server_catalog_decoder.py --stdin` fuera del repo entrega
   el mismo documento.
4. `file_decoder.run` abre un `.netflux` sintético por despacho
   explícito al perfil `gcpvpn` (sin registro `netflux` en `renz.py`),
   incluida la ruta C8 del worker (`engine.decode_file("netflux", raw)`).
5. `file_decoder.decode_text('netfluxvpn://...')` abre el enlace
   sintético, y `text_bridge.dispatch(link)` lo abre extremo a extremo
   (round-trip 7/7 archivo y texto ya verificado con
   `netflux.py` en el dossier; aquí se comprueba el despacho explícito:
   enlace, prefijo de esquema dentro del archivo, y rechazos de basura,
   esquema `netflux://` y sobre de otro perfil (7NET)).
6. Rechazo de entrada vacía, HTML, sobre truncado, campo `Servers`
   ausente y sobre de otro perfil (7NET como NetFlux).
7. Regresión `SlowDNS.PubKey`: el pase recursivo devuelve el hex de
   64 caracteres del modo principal (no se aplica ningún fallback).

Nota: NO existe un perfil `netflux` en `renz.py`: NetFlux despacha
explícitamente a `gcpvpn` porque ambos comparten material de claves y
catálogo en vivo, así que un sobre cifrado para uno abre con el otro;
el esquema `gcpvpn://` sobre un payload NetFlux tampoco se rechaza en
la ruta canónica de `renz` (las claves son las mismas). Lo que
distingue a los proveedores es la URL fija del catálogo y el despacho
explícito, no las claves. Si los blobs divergen algún día, eso sería
un cambio a decidir aparte; NetFlux queda solo online, sin puerto
offline, igual que GCP VPN.

Regresión RENZ completa (la ejecuta el analista de verificación;
NO corrida en esta entrega, que solo corrió `tests.test_netfluxvpn`):

```bash
~/workspace/http-custom-update/venv/bin/python -m unittest \
  tests.test_renz_family tests.test_sevennet_vpn \
  tests.test_renz_legacy_types tests.test_text_extra_structured \
  tests.test_cloud_c2_text
# Referencia de la entrega GCP: 27 tests, 1 fallo preexistente:
# test_phase_g_synthetic_reference_vectors (wyrvpn:// parity gap,
# verificado en worktree limpio de dc639d73).
```

Contadores de inventario RENZ: el retrabajo NO registra `netflux`,
así que el inventario queda en 16 sufijos, 23 protocolos y 14
perfiles, como en el head remoto (8af15a4a). `tests/test_renz_family.py`
(16/23), `tests/test_android_g_text_parity.py` (23) y
`scripts/android_d_renz_profiles.py` (16 sufijos, 14 perfiles) NO
necesitan ningún cambio, y el activo Android `renz_d_profiles.json`
queda intacto.

## Node

```bash
cd cloud/web && npm test -- tests/netfluxvpn-remote.test.mjs
```

`tests/netfluxvpn-remote.test.mjs` (modelo
`gcpvpn-remote.test.mjs`, fixture sintética en
`tests/golden/netfluxvpn_catalog_vectors.json`): descarga mock con DNS
validado y TLS, rechazo de redirecciones y de DNS privado, gateway
autenticado hacia el worker, y rechazo de resultados de worker
incompletos. La versión del catálogo público es **94**.

## Pendiente (no cubierto aquí)

- Muestra `.netflux` real o enlace `netfluxvpn://` real del teléfono de
  Pedro (estado actual: `VERIFIED_SYNTHETIC`).
- Confirmación de los 51 campos cortos de presentación.
- Fila `.netflux` en `docs/cloud/C0_FORMAT_MATRIX.csv` (ver C8 doc).
- Prueba en VPS tras el despliegue autorizado (`update all`).

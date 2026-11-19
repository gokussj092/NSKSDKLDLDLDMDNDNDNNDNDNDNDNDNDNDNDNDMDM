# GCP VPN — pruebas

## Python

```bash
cd ~/workspace/spdecode-patch
~/workspace/http-custom-update/venv/bin/python -m unittest tests.test_gcpvpn -v
```

`tests/test_gcpvpn.py` construye un catálogo sintético completo con
los generadores inversos de `tests/test_renz_family.py`
(`profile_fixture` para el sobre exterior, `special_fixture` para un
host, un sobre sensible PBKDF2-XXTEA-AES para credenciales y un sobre
principal para `SlowDNS.PubKey` con su valor hex de 64 caracteres) y
comprueba:

1. `codec.decode_catalog` + `render` devuelven el documento esperado.
2. `decode_provider_catalog('gcp-vpn', raw)` por el worker aislado
   entrega el mismo documento (`isPartial:false`).
3. El CLI `server_catalog_decoder.py --stdin` fuera del repo entrega
   el mismo documento.
4. `file_decoder.run` abre un `.gcpvpn` sintético por la ruta canónica.
5. Rechazo de entrada vacía, HTML, sobre truncado, campo `Servers`
   ausente y sobre de otro perfil (7NET como GCP).
6. Regresión `SlowDNS.PubKey`: el pase recursivo devuelve el hex de
   64 caracteres del modo principal (no se aplica ningún fallback).

Regresión RENZ completa (antes y después de esta entrega; el único
fallo es preexistente en HEAD limpio):

```bash
~/workspace/http-custom-update/venv/bin/python -m unittest \
  tests.test_renz_family tests.test_sevennet_vpn \
  tests.test_renz_legacy_types tests.test_text_extra_structured \
  tests.test_cloud_c2_text
# 27 tests, 1 fallo preexistente:
# test_phase_g_synthetic_reference_vectors (wyrvpn:// parity gap,
# verificado en worktree limpio de dc639d73).
```

## Node

```bash
cd cloud/web && npm test -- tests/gcpvpn-remote.test.mjs
```

`tests/gcpvpn-remote.test.mjs` (modelo
`sevennet-vpn-remote.test.mjs`, fixture sintética en
`tests/golden/gcpvpn_catalog_vectors.json`): descarga mock con DNS
validado y TLS, rechazo de redirecciones y de DNS privado, gateway
autenticado hacia el worker, y rechazo de resultados de worker
incompletos. La versión del catálogo público es **92**.

## Pendiente (no cubierto aquí)

- Muestra `.gcpvpn` real o enlace `gcpvpn://` real del teléfono de
  Pedro (estado actual: `VERIFIED_SYNTHETIC`).
- Confirmación de los 51 campos cortos de presentación.
- Prueba en VPS tras el despliegue autorizado (`update all`).

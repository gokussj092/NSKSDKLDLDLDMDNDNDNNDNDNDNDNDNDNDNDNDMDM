# PM Tunnel Lite — pruebas

## Python

```bash
cd ~/workspace/spdecode-patch
~/workspace/http-custom-update/venv/bin/python -m unittest tests.test_pmtunnel -v
```

`tests/test_pmtunnel.py` construye un catálogo sintético completo con
los generadores inversos del propio codec (`encrypt_mode0`,
`encrypt_special`, `encrypt_sensitive` con IV fijo) y comprueba (8 tests):

1. Known-answers del catálogo empaquetado: Threefish-256
   `encrypt(ceros)` idéntico al cifrador nativo (Unicorn), modo 0/1/2
   reproducen byte a byte los ciphertexts reales del APK (`Name` →
   `Please update config first`, `ServerIPHost` → `0.0.0.0`,
   `Username` → `qwfqeg`, `Password` → `qwegqeg`).
2. Catálogo fallback empaquetado `res/ae/e.js` (constante embebida,
   Version `1.0`, 1 servidor placeholder, host `0.0.0.0`) abre por
   `codec.decode_catalog` y por `file_decoder.run`.
3. `codec.decode_catalog` + `render` devuelven el documento esperado
   (todos los modos 0/1/2, incluidas las secciones anidadas `SlowDNS`,
   `V2Ray` y `UDPOptions`).
4. `decode_provider_catalog('pm-tunnel-lite', raw)` por el worker
   aislado entrega el mismo documento (`isPartial:false`).
5. El CLI `server_catalog_decoder.py --stdin` fuera del repo entrega
   el mismo documento.
6. `decode_catalog(..., redact=True)` nunca devuelve credenciales
   (hosts, usuarios, contraseñas, certs y cuenta de nivel superior en
   `None`) y conserva los campos no sensibles.
7. `file_decoder.run` abre un `.js` sintético, un
   `custom_payload.json` sintético (JSONArray modo 0) y un archivo con
   prefijo `pmtunnellite://`; `file_decoder.decode_text` abre el
   enlace sintético (insensible a mayúsculas en el esquema) y
   `text_bridge.dispatch` lo abre extremo a extremo; basura, esquema
   `pmtunnel://` y payload no-Base64 dan `None`.
8. Rechazo de entrada vacía, HTML, sobre truncado y catálogo sin
   `Servers`; `decode_drlb` diagnóstico rechaza basura (el positivo
   con fixture real vive en el dossier:
   `pmtunnel_files.py --self-test`, DEX v037 de 4,976 B).

Resultado en el overlay de validación (espejo del head remoto +
hunks aplicados): **8/8 tests OK**. Nota de entorno: en el espejo de
48 archivos faltan `MNR_TUNNEL_PLUS` y los 7 módulos `HANDLERS` de
`text_bridge.py`, que en el worktree completo sí existen; el test
extremo a extremo de texto se validó en el overlay con stubs
overlay-only (`is_profile_text → False`, `decode_text → None`) que NO
forman parte de la entrega. En el worktree completo el test corre
tal cual. La regresión RENZ completa la ejecuta el analista de
verificación en el worktree (el espejo no incluye
`tests/test_renz_family.py`); los cambios compartidos de PM son
puramente aditivos (una entrada en `PROVIDERS`, un id en la allowlist,
un bloque `if` en `text_bridge.py`, una entrada de broker, una
tarjeta, una entrada en la lista del gateway y una entrada de texto),
así que no alteran ninguna ruta existente.

El catálogo en vivo (Version 159, 10 servidores, 151 redes) se
descifra extremo a extremo con el mismo codec (`codec.decode_catalog`
sobre los bytes crudos == salida de `pmtunnel.py` del dossier, más
las secciones anidadas que ese descifrador descartaba); el live run
no se guarda en Git.

Versiones: `requirements.txt` fija `pycryptodome==3.23.0` (convención
del repo, igual que GCP/NetFlux); la verificación corrió en el venv
`http-custom-update`, que hoy reporta pycryptodome **4.4.0** (la API
`Crypto.Cipher.AES` usada es estable entre ambas; todos los tests
pasan ahí). Python 3.12.3.

## Node

```bash
cd cloud/web && npm test -- tests/pmtunnel-remote.test.mjs
```

`tests/pmtunnel-remote.test.mjs` (modelo
`gcpvpn-remote.test.mjs`, fixture sintética en
`tests/golden/pmtunnel_catalog_vectors.json`, generada con el mismo
catálogo sintético que `tests/test_pmtunnel.py` y verificada idéntica
a su `EXPECTED`): descarga mock con DNS validado y TLS, rechazo de
redirecciones y de DNS privado, gateway autenticado hacia el worker, y
rechazo de resultados de worker incompletos. La versión del catálogo
público es **95** (bump del coordinador).

**Pendiente de ejecución:** el espejo de 48 archivos no incluye los
módulos `cloud/web/lib/*.mjs` que `server-vpn-provider.mjs` importa
(p. ej. `http-conexion-protocol.mjs`), así que el test Node NO pudo
correrse en el overlay (`ERR_MODULE_NOT_FOUND` al importar el
broker). El test está escrito (sintaxis verificada con
`node --check`) y es una adaptación mecánica de
`gcpvpn-remote.test.mjs` (solo cambian fixture, ruta, providerId y
nombres); su ejecución completa queda para el worktree completo, a
cargo del coordinador. Los 5 tests son: fuente fija con DNS/TLS/ruta
exacta, rechazo de redirecciones, rechazo de DNS privado, broker
autenticado hacia el worker y rechazo de resultados incompletos.

## Pendiente (no cubierto aquí)

- Muestra `.js` real exportada por la app o enlace
  `pmtunnellite://` real del teléfono de Pedro (estado actual:
  `VERIFIED_SYNTHETIC`).
- Consumo interno de `Username`/`Password` por servidor (modo 2) sin
  verificar: no hay call site Java que pase modo 2.
- Prueba en VPS tras el despliegue autorizado (`update all`).

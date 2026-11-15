# RH Tunnel Lite 39.0.1 — REPRODUCE

Entorno: Python 3.12.3 (sistema). Via rapida opcional (argon2-cffi +
PyCryptodome) en el venv `~/workspace/http-custom-update/venv/bin/python`.
Sin red para los tests; con red para la descarga en vivo. Sin secretos:
ningun comando de este archivo lleva claves, tokens ni endpoints.

## 1. Tests del expediente (sin red, sin secretos)

```sh
cd analysis/com.rhtunnelmax.app/52
python3 -m unittest discover -s tests -v
# o, si pytest esta instalado:
python3 -m pytest tests/test_method.py -v
```

## 2. Self-test del script operativo (sin red salvo el chequeo en vivo)

```sh
cd ~/workspace/catalogs/rhtunnel
python3 <script-catalogo>.py --self-test
python3 <script-archivos>.py --self-test
```

Los nombres exactos y sus SHA-256 estan en `MANIFEST.json`:

- `RH_Tunnel_Lite.py` (catalogo) — SHA-256 `e0ec0da26c82e4f49432b2d7fbadc10d3909278359b24cc0316a8a5d221d0d1d`
- `RH_Tunnel_Lite_archivos.py` (archivos) — SHA-256 `7cd2a0287b0a66197f6a38d7c8fc84cc234de7d9f4fda59193731a7c098cdaed`

## 3. Catalogo en vivo (con red; el script replica la peticion de la app)

```sh
cd ~/workspace/catalogs/rhtunnel
python3 <script-catalogo>.py --url --out /tmp/catalogo-rhtunnel.json
```

Si la descarga se trunca (cuerpo chunked), el script reintenta; como
ultimo recurso, descargar con curl y usar `--raw` (ver TESTING.md de
origen). La salida es el JSON de resultado limpio (regla 2026-11-15:
solo datos del catalogo, todo descifrado, sin APIs de descarga).

## 4. Archivos

```sh
cd ~/workspace/catalogs/rhtunnel
python3 <script-archivos>.py --self-test
```

Las muestras (reales o sinteticas) y sus hashes estan en `MANIFEST.json`
(`inputs`). Las muestras reales de usuario NO se copian a este expediente.

## 5. Herramientas de investigacion (tools/)

Ver `tools/README.md`: cada script indica su entrada (ruta al jadx o al
`.so` extraido) y su proposito. Ninguno contiene claves ni endpoints.

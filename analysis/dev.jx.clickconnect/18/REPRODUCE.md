# VLX Tunnel VPN VLX v14 — REPRODUCE

Entorno: Python 3.12.3 (sistema). Via rapida opcional (argon2-cffi +
PyCryptodome) en el venv `~/workspace/http-custom-update/venv/bin/python`.
Sin red para los tests; con red para la descarga en vivo. Sin secretos:
ningun comando de este archivo lleva claves, tokens ni endpoints.

## 1. Tests del expediente (sin red, sin secretos)

```sh
cd analysis/dev.jx.clickconnect/18
python3 -m unittest discover -s tests -v
# o, si pytest esta instalado:
python3 -m pytest tests/test_method.py -v
```

## 2. Self-test del script operativo (sin red salvo el chequeo en vivo)

```sh
cd ~/workspace/catalogs/vlx
python3 <script-catalogo>.py --self-test
python3 <script-archivos>.py --self-test
```

Los nombres exactos y sus SHA-256 estan en `MANIFEST.json`:

- `VLX_Tunnel_VPN.py` (catalogo) — SHA-256 `908ab7a911661594cbf9ecbc8694236b2d2078a8a6c095c56b4d952e201432c1`
- `VLX_Tunnel_VPN_archivos.py` (archivos) — SHA-256 `899852131e637da6cc2762147e91ae8eeb78ccba99786a72d27daaf412095213`

## 3. Catalogo en vivo (con red; el script replica la peticion de la app)

```sh
cd ~/workspace/catalogs/vlx
python3 <script-catalogo>.py --url --out /tmp/catalogo-vlx.json
```

Si la descarga se trunca (cuerpo chunked), el script reintenta; como
ultimo recurso, descargar con curl y usar `--raw` (ver TESTING.md de
origen). La salida es el JSON de resultado limpio (regla 2026-11-15:
solo datos del catalogo, todo descifrado, sin APIs de descarga).

## 4. Archivos

```sh
cd ~/workspace/catalogs/vlx
python3 <script-archivos>.py --self-test
```

Las muestras (reales o sinteticas) y sus hashes estan en `MANIFEST.json`
(`inputs`). Las muestras reales de usuario NO se copian a este expediente.

## 5. Herramientas de investigacion (tools/)

Ver `tools/README.md`: cada script indica su entrada (ruta al jadx o al
`.so` extraido) y su proposito. Ninguno contiene claves ni endpoints.

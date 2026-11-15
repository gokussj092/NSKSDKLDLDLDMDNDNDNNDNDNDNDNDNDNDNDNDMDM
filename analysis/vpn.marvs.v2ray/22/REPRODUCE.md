# RH Tunnel Secure (Marvs V2Ray) RHV1 — REPRODUCE

Entorno: Python 3.12.3 (sistema). Via rapida opcional (argon2-cffi +
PyCryptodome) en el venv `~/workspace/http-custom-update/venv/bin/python`.
Sin red para los tests; con red para la descarga en vivo. Sin secretos:
ningun comando de este archivo lleva claves, tokens ni endpoints.

## 1. Tests del expediente (sin red, sin secretos)

```sh
cd analysis/vpn.marvs.v2ray/22
python3 -m unittest discover -s tests -v
# o, si pytest esta instalado:
python3 -m pytest tests/test_method.py -v
```

## 2. Self-test del script operativo (sin red salvo el chequeo en vivo)

```sh
cd ~/workspace/catalogs/marvsv2ray
python3 <script-catalogo>.py --self-test
python3 <script-archivos>.py --self-test
```

Los nombres exactos y sus SHA-256 estan en `MANIFEST.json`:

- `Marvs_V2Ray.py` (catalogo) — SHA-256 `5edb448085be9395fad392980efe74d10e4d0cbecf898971a14ed60238c5e745`
- `Marvs_V2Ray_archivos.py` (archivos) — SHA-256 `843412da7bdb32a85416d45afa8ee87a1269766783e070778010b244063fb81d`

## 3. Catalogo en vivo (con red; el script replica la peticion de la app)

```sh
cd ~/workspace/catalogs/marvsv2ray
python3 <script-catalogo>.py --url --out /tmp/catalogo-marvsv2ray.json
```

Si la descarga se trunca (cuerpo chunked), el script reintenta; como
ultimo recurso, descargar con curl y usar `--raw` (ver TESTING.md de
origen). La salida es el JSON de resultado limpio (regla 2026-11-15:
solo datos del catalogo, todo descifrado, sin APIs de descarga).

## 4. Archivos

```sh
cd ~/workspace/catalogs/marvsv2ray
python3 <script-archivos>.py --self-test
```

Las muestras (reales o sinteticas) y sus hashes estan en `MANIFEST.json`
(`inputs`). Las muestras reales de usuario NO se copian a este expediente.

## 5. Herramientas de investigacion (tools/)

Ver `tools/README.md`: cada script indica su entrada (ruta al jadx o al
`.so` extraido) y su proposito. Ninguno contiene claves ni endpoints.

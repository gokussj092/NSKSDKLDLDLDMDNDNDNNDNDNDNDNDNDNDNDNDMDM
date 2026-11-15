# Bee VPN 1.10.11.2 — REPRODUCE

Entorno: Python 3.12.3 (sistema). Via rapida opcional (argon2-cffi +
PyCryptodome) en el venv `~/workspace/http-custom-update/venv/bin/python`.
Sin red para los tests; con red para la descarga en vivo. Sin secretos:
ningun comando de este archivo lleva claves, tokens ni endpoints.

## 1. Tests del expediente (sin red, sin secretos)

```sh
cd analysis/co.strongteam.beevpn/65
python3 -m unittest discover -s tests -v
# o, si pytest esta instalado:
python3 -m pytest tests/test_method.py -v
```

## 2. Self-test del script operativo (sin red salvo el chequeo en vivo)

```sh
cd ~/workspace/catalogs/beevpn
python3 <script-catalogo>.py --self-test
python3 <script-archivos>.py --self-test
```

Los nombres exactos y sus SHA-256 estan en `MANIFEST.json`:

- `Bee_VPN.py` (catalogo) — SHA-256 `766e36c818e97e8993f2e4ceb642cf80b902eb94de386f06ca8e829bfc12ccdb`
- `Bee_VPN_archivos.py` (archivos) — SHA-256 `7c247e179fe8bbc56e8a3e9cfdacc8a906c206f05e50c8cce4de1a33f1cc0d04`

## 3. Catalogo en vivo (con red; el script replica la peticion de la app)

```sh
cd ~/workspace/catalogs/beevpn
python3 <script-catalogo>.py --url --out /tmp/catalogo-beevpn.json
```

Si la descarga se trunca (cuerpo chunked), el script reintenta; como
ultimo recurso, descargar con curl y usar `--raw` (ver TESTING.md de
origen). La salida es el JSON de resultado limpio (regla 2026-11-15:
solo datos del catalogo, todo descifrado, sin APIs de descarga).

## 4. Archivos

```sh
cd ~/workspace/catalogs/beevpn
python3 <script-archivos>.py --self-test
```

Las muestras (reales o sinteticas) y sus hashes estan en `MANIFEST.json`
(`inputs`). Las muestras reales de usuario NO se copian a este expediente.

## 5. Herramientas de investigacion (tools/)

Ver `tools/README.md`: cada script indica su entrada (ruta al jadx o al
`.so` extraido) y su proposito. Ninguno contiene claves ni endpoints.

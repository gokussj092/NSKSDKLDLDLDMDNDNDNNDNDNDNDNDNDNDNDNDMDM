# Click Tunnel 1.0 — REPRODUCE

Entorno: Python 3.12.3 del sistema; venv con pycryptodome 4.4.0
(`~/workspace/http-custom-update/venv/bin/python`) para ejecutar los
scripts de Click Tunnel. Sin red para los tests; con red para la
descarga en vivo. Sin secretos: ningún comando de este archivo lleva
claves, tokens ni endpoints completos (la URL del catálogo vive en la
constante `CATALOG_URL` del script operativo).

## 1. Tests del expediente (sin red, sin secretos)

```sh
cd analysis/com.clicktunnel.vpn/1
~/workspace/http-custom-update/venv/bin/python -m unittest discover -s tests -v
```

El test carga el script operativo por ruta
(`decoders/Python/apps/Click_Tunnel/Click_Tunnel.py` del staging) y
descifra el fixture `tests/fixtures/bundled_catalog.js` (copia del
asset `res/raw/noobdev.js` del APK: catálogo v1.0.0, 1 servidor,
1 tweak; campos cifrados, sin valores en claro). También comprueba que
`decode()` devuelve el documento CON `DefUpdateURL`/`updater` y que
quitando esas dos claves queda el documento de resultado limpio, y que
`run()` con entrada inválida devuelve `None`.

## 2. Self-test del script operativo (sin red)

```sh
cd decoders/Python/apps/Click_Tunnel
~/workspace/http-custom-update/venv/bin/python Click_Tunnel_archivos.py --self-test
# {"self_test": "pass", "profiles": 8, "passed": 8, "field_counts": [31, 27, 27, 27, 27, 27, 31, 27]}
python3 -m py_compile Click_Tunnel.py Click_Tunnel_archivos.py
```

Los SHA-256 exactos están en `MANIFEST.json`:

- `Click_Tunnel.py` — SHA-256 `59c4c641d8c49860656b9d638fe4b58928cfeb092e327cb870e5b36624a30b86`
  (NOTA: el README de origen registra `d04e4c45…`; está desactualizado)
- `Click_Tunnel_archivos.py` — SHA-256 `756cfb5e935baa9c56909a3638a40891432c7e0f663d380193c5b87296ef450d`

## 3. Catálogo en vivo (con red; el script replica la petición de la app)

```sh
cd decoders/Python/apps/Click_Tunnel
~/workspace/http-custom-update/venv/bin/python Click_Tunnel.py --url --summary
# {"Version": "5.1.8", "Servers": 7, "Tweaks": 18, ...}
~/workspace/http-custom-update/venv/bin/python Click_Tunnel.py --url -o /tmp/click_full.json
# comparar byte por byte con ~/workspace/catalogs/clicktunnel/live.json
# (SHA-256 9bb6f8e5991203ea82220c919ddce59d7f4872687aee0e90f002184007ecd8c8)
cmp /tmp/click_full.json ~/workspace/catalogs/clicktunnel/live.json
```

La salida guardada es el JSON de resultado limpio (regla 2026-11-15:
`main()` quita `DefUpdateURL` y `updater` al guardar/imprimir).
OJO: `decode()`/`run()` en memoria SÍ devuelven esas dos claves; ver
ANALYSIS.md §2.

## 4. Catálogo incrustado (sin red)

```sh
~/workspace/http-custom-update/venv/bin/python Click_Tunnel.py --apks Click_Tunnel_1.0_1_koun.apks --summary
# v1.0.0, 1 servidor, 1 tweak
```

El `.apks` es el archivo aportado por el propietario; no se guarda en Git.

# tools/ — Click Tunnel

Este expediente NO copia las herramientas de investigación: viven en
`~/workspace/catalogs/clicktunnel/work/` (decompilación jadx 1.5.3
`jadx-out/` y `jadx-deob/` con las 3.777 llamadas `Cp0.j` descifradas,
`cp0.py` — puerto verificado del descifrador de cadenas —,
`cp0_mapping.json`, `xxtea_test.py`, `fields_test.py`,
`live_response.txt`, `live_outer.json`, `manifest.xml`,
`raw/res/raw/noobdev.js`). No se copian porque referencian respuestas
vivas, el APK aportado y material de análisis; el expediente conserva
sus hashes y resultados en `MANIFEST.json` / `RESULTS.md`.

Lo reproducible desde este expediente, sin red y sin secretos:

- `~/workspace/http-custom-update/venv/bin/python -m unittest discover -s tests -v`
  (fixture: asset incrustado `res/raw/noobdev.js`).
- `~/workspace/http-custom-update/venv/bin/python <staging>/decoders/Python/apps/Click_Tunnel/Click_Tunnel_archivos.py --self-test` (8/8).
- `~/workspace/http-custom-update/venv/bin/python <staging>/decoders/Python/apps/Click_Tunnel/Click_Tunnel.py --url --summary`
  (con red; GET plano, sin auth).

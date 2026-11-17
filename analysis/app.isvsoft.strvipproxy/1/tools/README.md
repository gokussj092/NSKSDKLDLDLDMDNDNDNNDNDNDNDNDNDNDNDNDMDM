# tools/ — STR VIP Proxy

Este expediente NO copia las herramientas de investigación: viven en
`~/workspace/catalogs/strvipproxy/work/` (emulador Unicorn `emu.py`,
desensamblados `dis_*.txt`, `sign_headers.py`, `fetch_gzip.py`,
`dec_all.py`, `test_aes.py` — cruce AES-GCM con `cryptography` —,
`live_full.bin` / `live_servers.bin`, `bundled/`, volcados DEX).
No se copian porque referencian respuestas vivas, el APK aportado y
material de análisis; el expediente conserva sus hashes y resultados
en `MANIFEST.json` / `RESULTS.md`.

Lo reproducible desde este expediente, sin red y sin secretos:

- `python3 -m unittest discover -s tests -v` (fixture sintético).
- `python3 <staging>/decoders/Python/apps/STR_VIP_Proxy/STR_VIP_Proxy_archivos.py --self-test` (12/12).
- `python3 <staging>/decoders/Python/apps/STR_VIP_Proxy/STR_VIP_Proxy.py --url --summary`
  (con red; replica la petición exacta de la app, con App-Proof).

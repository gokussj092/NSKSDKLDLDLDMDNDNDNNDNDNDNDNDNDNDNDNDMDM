# STR VIP Proxy 1.42.5 — REPRODUCE

Entorno: Python 3.12.3 (sistema). Solo stdlib; sin red para los tests;
con red para la descarga en vivo. Sin secretos: ningún comando de este
archivo lleva claves, tokens ni endpoints completos (la URL del
catálogo vive en la constante `CATALOG_URL` del script operativo).

## 1. Tests del expediente (sin red, sin secretos)

```sh
cd analysis/app.isvsoft.strvipproxy/1
python3 -m unittest discover -s tests -v
```

El test carga el script operativo por ruta
(`decoders/Python/apps/STR_VIP_Proxy/STR_VIP_Proxy.py` del staging) y
descifra el fixture sintético `tests/fixtures/synthetic_catalog.json`
(valores TEST-NET `198.51.100.1` / `test-payload` cifrados con el propio
`encrypt_token` del script; ningún dato real). También comprueba que
`run()` con entrada inválida devuelve `None`.

## 2. Self-test del script operativo (sin red)

```sh
cd decoders/Python/apps/STR_VIP_Proxy
python3 STR_VIP_Proxy_archivos.py --self-test
# {"self_test": "pass", "cases": 12, "passed": 12, "failed": []}
python3 -m py_compile STR_VIP_Proxy.py STR_VIP_Proxy_archivos.py
```

Los SHA-256 exactos están en `MANIFEST.json`:

- `STR_VIP_Proxy.py` — SHA-256 `cd539bf6e7027f987b046b8ef1684cc78ed38840bcf31e2b48176b9b62681652`
- `STR_VIP_Proxy_archivos.py` — SHA-256 `48b5fdbd3bee418f5647e9139d69cdf846f38a5b320319d97ea0960694ed99f8`

## 3. Catálogo en vivo (con red; el script replica la petición de la app)

```sh
cd decoders/Python/apps/STR_VIP_Proxy
python3 STR_VIP_Proxy.py --url --summary
# {"catalog_version": "1.0.31", "servers": 21, "tweaks": 686, ...}
python3 STR_VIP_Proxy.py --url -o /tmp/str_full.json
# comparar byte por byte con ~/workspace/catalogs/strvipproxy/live.json
# (SHA-256 ed3cd7622e725cca1ab11d543bc1f87758a1927155e642b360e922d479add6c1)
cmp /tmp/str_full.json ~/workspace/catalogs/strvipproxy/live.json
```

La salida es el JSON de resultado limpio (regla 2026-11-15: solo datos
del catálogo, todo descifrado, sin APIs de descarga). Si la descarga se
corta (el servidor ignora `Range` y la respuesta full se trunca por
HTTP/1.1 a través de algunos proxies), el script reintenta y usa
`curl --http2` como fallback — curl existe en este entorno, pero NO en
la imagen del worker (ver ANALYSIS.md §5).

## 4. Catálogo incrustado (sin red)

```sh
python3 STR_VIP_Proxy.py --apks base.apk --summary
# v1.0.0, 9 servidores, 11 tweaks
```

`base.apk` es el APK aportado por el propietario; no se guarda en Git.

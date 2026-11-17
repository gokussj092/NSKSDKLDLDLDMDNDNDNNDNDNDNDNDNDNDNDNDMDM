# Click Tunnel — catálogo y archivos

App: Click Tunnel, paquete `com.clicktunnel.vpn`, versionCode 1,
versionName 1.0. Archivo analizado: `Click_Tunnel_1.0_1_koun.apks`
(52.871.766 B, SHA-256
`cd9189cf3c8c64317c175126c94b0684197a3ce1ed45b25942386f89b049f80a`).

## Catálogo (`Click_Tunnel.py`, necesita pycryptodome)

- Descarga: `GET https://raw.githubusercontent.com/uptechvpn/Click-Tunnel/refs/heads/main/Click%20Tunnel`
  (URL fija, sin parámetros ni cabeceras propias; `User-Agent: Dalvik/2.1.0`).
- Descifrado: Base64 → XXTEA modificado (delta `0x9A7393B4`, clave =
  primeros 16 bytes del UTF-8 de 32× U+3164) → JSON; campos de texto
  con AES-256/CFB (clave = SHA-256 de semilla de 83 caracteres) y
  tweaks con AES/CBC/PKCS7 (clave = hex MD5 de semilla de 63 caracteres).
- En vivo (2026-11-17, re-corrido byte por byte): v5.1.8, 7 servidores,
  18 tweaks, 0 valores sin descifrar.
- El JSON de resultado NO incluye las APIs de descarga (regla del
  proyecto): `decode()`/`run()` devuelven el documento con
  `DefUpdateURL` y `updater` y es el puente supplied quien debe quitar
  esas dos claves (ver `REPORT.md`: hace falta una rama en
  `supplied_bridge.py:decode_one`, como las de RH/JK); `main()` del
  script ya las quita al guardar/imprimir.

## Archivos (`.sup` / `.wsuiou`) (`Click_Tunnel_archivos.py`, pycryptodome)

- Formato: Base64 de `nonce[12] || ciphertext || tag[16]` → AES/GCM;
  el texto descifrado empieza por `Click Tunnel` y el resto es JSON.
  Campos internos (`Payload`, `SNIHost`, etc.) van cifrados
  individualmente con la misma clave y se descifran al usarlos.
- La exportación escribe `.wsuiou` pero el filtro VIEW del manifiesto
  es `.sup`; el lector acepta ambas.
- **`xfsd://` NO es un esquema registrado:** es solo una clave de nube
  de 20 caracteres (Firebase Storage); no hay clave real para verificar
  la descarga, así que NO se registra como formato de texto.
- **Probado:** `--self-test` 8/8 perfiles (round-trip sintético).
  **Sin archivo real:** no existe ningún `.sup`/`.wsuiou` real
  exportado por la app; la confirmación extremo a extremo sigue pendiente.

## Uso

```sh
~/workspace/http-custom-update/venv/bin/python Click_Tunnel.py --url --summary
~/workspace/http-custom-update/venv/bin/python Click_Tunnel.py --url -o catalogo.json
~/workspace/http-custom-update/venv/bin/python Click_Tunnel_archivos.py --self-test
~/workspace/http-custom-update/venv/bin/python Click_Tunnel_archivos.py perfil.sup -o perfil.json
```

Necesita pycryptodome (`Crypto.Cipher.AES`): está en el
`requirements.txt` raíz del repo (`pycryptodome==3.23.0`), así que la
imagen del worker lo tiene. Estado de integración: pendiente de subida
(staging, sin deploy, sin merge).

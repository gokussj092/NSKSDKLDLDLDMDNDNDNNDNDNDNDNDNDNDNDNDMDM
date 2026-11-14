# UDP Thunder VPN 1.5 — decodificador de catálogo (SP-DECODE)

- **App:** UDP Thunder VPN, paquete `com.udpthunder.vpn`, versión 1.5,
  versionCode 6, minSdk 23, targetSdk 36. Versión pública de Google Play
  (actualizada 23 dic 2025); descargada de APKPure (APKMirror no tenía
  listado). XAPK SHA-256
  `e26a57c6db5d6e34d0280f90bd6b302db9f5c4fc0c98ab06fb1a6a70e9d4e7b8`.
  Solo variante armeabi-v7a (32 bits) para esta versión.
- **Sin cobertura previa en el repo SP-DECODE** (86 carpetas revisadas en
  la rama `feat/nuevas-integraciones`; `com.litron.udp` es otra app).

## Catálogo

- **URL + petición exacta:** `GET
  https://freedomnavigate.com/updater/2ee4ec6e75df8910d98e7bb33f12e1`
  — GET plano (Volley `StringRequest` en `UDPClient.i`), sin cabeceras
  propias ni autenticación. El servidor responde HTTP 200 con
  `Content-Length: 40424` y a veces corta la conexión a mitad del
  cuerpo; el script reanuda por rangos (igual que el de APNA Tunnel
  Lite). User-Agent enviado: `Dalvik/2.1.0` con
  `Accept-Encoding: identity` (aceptado por el servidor).
- **Cifrado:** cuerpo = una línea Base64 → **XXTEA modificado**
  (delta `0x9E5729B1`, clave de formato `"...|..."`, última palabra =
  longitud del texto plano) → JSON. Es el mismo formato de APNA Tunnel
  Lite / TRM Tunnel / HX Tunnel / Handsome Fast / RJC Tunnel / HAMARA
  TUNNEL LITE (misma clave de catálogo y mismo delta); solo cambian la
  URL, el nombre del asset (`aug.json`) y la versión. La app descifra
  con `wh.c` (clase `wh`, método `c(String, String)`).
- **Prueba en vivo (2026-11-13, con `--url`):** HTTP 200, 40.424 B,
  **Version 27.6, UDPVersion v2, 23 servidores libres** (0 premium, 0
  VIP, 0 privados) y **1 entrada de Payloads** (plantilla con payload
  vacío, host/puerto `"Pulled"`). Servidores en dos categorías:
  `ocsudp` y `ocsdnstt`; los campos de puerto vienen vacíos en el
  catálogo.
- **Campos Username/Password de nivel superior:** vienen cifrados con
  el mismo XXTEA (Base64 → XXTEA → texto) y son las credenciales SSH
  por defecto de los servidores (los servidores individuales traen
  username/password vacíos). El script los abre por defecto; la opción
  `--keep-encoded` los deja como Base64.
- **Asset incluido (`aug.json`):** Version 18.0, 25 servidores libres,
  1 payload. La app guarda el catálogo descargado como
  `filesDir/aug.json` y si no existe usa este asset.

## Archivos

- **Sin formato propio de perfil exportable/importable.** No hay
  intent-filter de archivos en el manifiesto, no hay esquema URI propio
  y no hay picker de archivos en la app. Lo único que la app guarda
  como archivo es el catálogo mismo (`filesDir/aug.json`).
- `UDP_Thunder_VPN_archivos.py` descifra ese archivo (o el asset) con
  el mismo método del catálogo. Sin `.sks`.
- `libputils.so` (en `config.armeabi_v7a.apk`) expone `pEncrypt` /
  `pDecrypt` JNI (`udp.thunder.vpn.utils.PUtils`), pero `pDecrypt` no
  tiene llamadores Java y `pEncrypt` solo se usa dentro del hilo del
  túnel (`lI.run`) para tráfico en vivo, no para archivos. No hay
  formato de archivo que descifrar con esa librería.

## Esquemas de texto

- **Ninguno propio** (solo `genericidp`/`recaptcha` de Firebase). Solo
  los estándares vmess/vless/ss/trojan, que SP-DECODE ya cubre.

## Librerías nativas (todas en config.armeabi_v7a.apk)

`libdatastore_shared_counter.so`, `libdns.so`, `libpdnsd.so`,
`libputils.so` (2.139.576 B), `libtun2socks.so`, `libudpq.so`,
`libudpqtwo.so`. El base APK no trae `.so`. El catálogo es Java puro.

## Archivos entregados

- `UDP_Thunder_VPN.py` — catálogo, stdlib puro, `decode()` + `run()` +
  CLI `--url/--file/--asset/--stdin/--self-test/-o/--summary/
  --keep-encoded`. `--self-test` 10/10.
- `UDP_Thunder_VPN_archivos.py` — archivo `aug.json` offline (importa
  el descifrador de `UDP_Thunder_VPN.py`; mantener juntos).
  `--self-test` 5/5.
- `UDP_Thunder_VPN.png` — 512×512 RGBA (icono del XAPK).
- `aug.json` — asset cifrado incluido (v18.0, para `--self-test` /
  `--asset`).

## Pendiente

- Nada para cerrar el método: catálogo verificado en vivo de extremo
  a extremo y asset incluido verificado. Si el servidor rota la clave
  o cambia la URL/formato, el script informará el fallo sin inventar
  servidores.

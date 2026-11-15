# Siam VPN 4.9 (siam.pro.net)

Catálogo y archivos `profile.json` de Siam VPN, analizados de su APK oficial
(versión 4.9, versionCode 49, minSdk 32, la versión pública en Google Play)
y con los scripts probados con una descarga real. Python 3.10+ con solo la
biblioteca estándar; formato de proveedor del repo (`decode()` + `run()` +
CLI `--url`). No hay cobertura previa en el repo (se revisaron las 86
carpetas de `decoders/Python/apps/`; `Thailand_VPN` es otra app).

## Catálogo (`Siam_VPN.py`)

- **Descarga:** `GET http://unifi.thai-vpn.com/app-patch/patch-siam-3`
  (GET plano, sin cabeceras propias ni autenticación; la app lee la URL
  de la preferencia `key_url`, cuyo valor por defecto es este endpoint).
  El servidor responde HTTP 200 con una sola línea Base64 (~143576
  caracteres; `Last-Modified: Wed, 11 Nov 2026`).
- **Cifrado:** streaming AEAD, una variante ligeramente modificada del
  `AesGcmHkdfStreaming` de Google Tink que la app lleva vendada:
  - `IKM = PBKDF2-HmacSHA256(contraseña = preferencia "key_secured",
    sal = b"MY_APP_FIXED_SALT_V1", 100000 iteraciones, 32 bytes)`.
  - Cabecera de 40 bytes: `[0x28][sal: 32 bytes][prefijo de nonce: 7 bytes]`
    (el primer byte es la longitud de la cabecera, no un byte de versión).
  - `clave = HKDF-SHA256(IKM, sal de cabecera,
    info = b"MY_SECURE_JSON_STREAM_V1", 32 bytes)`.
  - El blob es una secuencia de bloques de 4096 bytes contados desde el
    inicio del archivo: el bloque 0 lleva la cabecera (40) más el primer
    segmento (4056 bytes = 4040 de texto plano + 16 de etiqueta); cada
    bloque siguiente es un segmento (4096 = 4080 + 16), y el último
    bloque es el segmento final (más corto). El número de segmento es
    el índice de bloque (0, 1, 2, ...); el último lleva el flag de
    último segmento. Cada segmento es AES-256-GCM, nonce = prefijo (7)
    + número de segmento (4 bytes, big endian) + flag (1 byte), sin
    datos adicionales autenticados. La implementación es AES-GCM en
    Python puro (núcleo AES reutilizado del lote de AR PRO + GHASH);
    el descifrado completo tarda ~5 s.
  - El `key_secured` es una constante de formato que la propia app
    escribe como valor por defecto en sus preferencias; no es una
    contraseña de usuario.
- **Prueba en vivo (2026-11-13, `--url`):** Version **8.70**, Message
  `update`, **26 servidores** (todos flag `th`; 6 Direct Connection
  OpenVPN, 1 UDP, 19 Default) y **23 redes/payloads**. El catálogo no
  marca libre/premium en los servidores; 10 payloads son de ítem
  (`PayloadFlag "true"`, su PayloadInfo dice "ต้องมีไอเท็ม ...") y 13
  son por operadora (AIS 7, DTAC 5, MY 1). Los campos `ServerIP`,
  `Username`, `Password`, `setOpenVPN`, `Payload`, `SquidProxy` y
  otros vienen cifrados con el esquema `ED:` (ver abajo) y el script
  los descifra: por ejemplo `ServerIP` es un hostname
  (`readyidc-o-1.opensignal.uk`, `openvpn-1.thaivpn.uk`, ...), y un
  `Payload` es un HTTP payload legible con placeholders `[crlf]`,
  `[host]` y `[ua]`.
- **Esquema `ED:` (Lo41.a):** `"ED:" + Base32(texto UTF-8)`. Los campos
  de servidor y de red listados en el script se descifran así; un valor
  que no es `ED:` pero es Base64 válido se descifra como respaldo, como
  hace la app. `--keep-ed` deja los valores `ED:` tal cual.
- **Endpoint secundario (`--ping`):**
  `GET https://www.thai-vpn.com/ayothaya/ping.json` → JSON plano con
  **58 entradas** (8 hosts de ISP tailandeses + TH-01..TH-50, puerto
  82). Es una lista de latencia, no el catálogo.
- **Uso:** `python3 Siam_VPN.py --url [-o catalogo.json]`,
  `python3 Siam_VPN.py --file blob_guardado`,
  `python3 Siam_VPN.py --ping`, `python3 Siam_VPN.py --self-test`
  (7/7 OK).

## Archivos (`Siam_VPN_archivos.py`)

- **Formato `profile.json`** (el archivo que la app lee de `filesDir/`
  al arrancar): una línea de texto → Base64 estándar (el `Ld32.i` de
  la app: ignora caracteres fuera del alfabeto, `=` termina la
  entrada) → XXTEA descifrar (el `Lk20.e` de la app; delta
  `0x2e0ba747`, clave = los primeros 16 bytes UTF-8 de
  `MainDetail.b()`, `"BamINlswE$re@+G"`; la última palabra guarda la
  longitud del texto plano) → JSON con `Version`, `Message`,
  `Servers`, `Networks` y `setOpenVPN`.
- **Migración de claves:** el script reproduce la migración que hace
  la app al cargar el archivo (solo cuando la clave vieja existe):
  `Name → ServerName`, `Flag → ServerFlag`, `SSLPort →
  OpenVPNSSLPort` y `SSHSSLPort`, `OvpnCertificate → setOpenVPN`,
  `AutoLogIn`/`MultiCert` booleano → `"true"`/`"false"`;
  en redes `Name → PayloadName`, `Flag → PayloadFlag`,
  `Info → PayloadInfo`, `UseDefProxy` booleano → string. Ojo: como
  hace la app, si un servidor trae `ServerDNS` su valor se sustituye
  por el de `ServerIP`, y en redes un `ServerDNS` presente se vacía.
  La salida refleja el perfil tal como la app lo ve en memoria, no
  el JSON tal como venía en el archivo.
- **Campos `ED:`** se descifran igual que en el catálogo.
- **Un JSON plano** (por ejemplo, el catálogo guardado por
  `Siam_VPN.py`) también se acepta: solo se normaliza y se descifran
  sus campos `ED:`.
- **Uso:** `python3 Siam_VPN_archivos.py profile.json [-o salida.json]`,
  `python3 Siam_VPN_archivos.py --self-test` (4/4 OK: round-trip
  XXTEA con claves viejas, JSON plano, cifrado corrupto que debe
  fallar, y round-trip `ED:`).

## Sin esquema URI de texto propio

El manifiesto no declara ningún intent-filter `VIEW` ni esquema
propio (no hay `siam://`); solo aparecen los enlaces estándar
`vmess://`, `vless://`, `ss://`, `trojan://`, `socks://`,
`hysteria2://` y `wireguard://`, que SP-DECODE ya cubre. Tampoco hay
formato `.sks`.

## Entregables

- `Siam_VPN.py` (SHA-256 `a7a288977f64ee47d9e5dd88cc0bcf4d67c6a046f867ec2f1a50766688394c54`)
- `Siam_VPN_archivos.py` (SHA-256 `0108d3de7b7a24b6f45d110531cbe75d1796f48b9202a721d2777bc7830c0ca7`)
- `Siam_VPN.png` 512×512 (SHA-256 `75f8f92d96de732bb7b3a04f486bc7f6e88110ddfac64f6875d7c08c7db7a151`;
  el XAPK trae `icon.png` como JPEG 512×512, convertido a PNG)

## Pendiente

- **Confirmación de extremo a extremo con un `profile.json` real
  exportado por la app en un teléfono.** El camino Base64 → XXTEA
  está verificado por round-trip y reproduce el bytecode de la app
  al detalle, pero ningún `profile.json` real estaba disponible para
  probarlo. Si el formato cambia en una versión nueva, hay que
  re-analizar `libapi-siam.so` (la clave XXTEA vive ahí) y `Lk20.e`.
- Si el servidor rota la clave (`key_secured`) o cambia la URL, el
  script fallará con `GCM_TAG` y habrá que re-analizar la versión
  nueva de la app; el script nunca inventa servidores.
- El catálogo en vivo es la versión 8.70; si la app se actualiza en
  Google Play, conviene re-verificar que el método sigue igual.

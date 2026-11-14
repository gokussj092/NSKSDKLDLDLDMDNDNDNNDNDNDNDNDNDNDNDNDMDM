# E-SAN VPN 1.6.4 — catálogo

Package `com.misaki.esanvpn`, versionCode 74, versionName 1.6.4,
minSdk 32, targetSdk 37. App solo de 32 bits (el split
`config.armeabi_v7a.apk` lleva todas las librerías nativas; el APK base
no tiene ninguna). XAPK ya extraído en `apk/` (SHA-256 del XAPK:
`a1dee0f3d19f8c983cc8aad4617cc2cafcecc4916e244257e391c51ad1359857`).
SP-DECODE no cubría esta app (sin entrada "esan" ni "misaki" en
`decoders.json` ni en `grupos.json`, rama `feat/nuevas-integraciones`).

Librerías nativas (todas en `config.armeabi_v7a.apk`): `libapi-esan.so`
(3.112 B), `libdns.so`, `libhysteria.so`, `libovpncli.so`, `libpdnsd.so`,
`libtun2socks.so`. Las cadenas están ofuscadas con LSParanoid (clase
`Ln51;`, método `j(J)`); las 1.190/1.190 se resolvieron con el
`paranoid-deobfuscator` de referencia (3.0.2). No se usó el port Python
de LSParanoid del lote 2 (no reproduce los resultados correctos).

## Método del catálogo

La app descarga el catálogo con una petición GET simple (WorkManager,
sin autenticación ni parámetros):

`GET https://e-san-vpn.in.net/ServerUpdate/e-san-vpn.json`

El servidor es Cloudflare y rechaza el User-Agent por defecto de
Python-urllib (403); con un User-Agent Dalvik/Java/navegador responde
200. El script usa `Dalvik/2.1.0 (Linux; U; Android 14)`.
Respuesta: una línea de Base64 (26.996 B) → 20.247 B cifrados.

El sobre es una variante de **Tink StreamingAead** (clases `jc0`/`p5`/
`my0`/`t1` del APK):

1. Contraseña = valor del ajuste `key_secured` (por defecto
   `l{0[$~A1grg3+k1HhyMK7.IlF!m%^B0AKfqpOc0g`, en `tk3.<init>`).
   Es la contraseña del formato, no una credencial de usuario.
2. `PBKDF2-HmacSHA256`, 100.000 iteraciones, clave de 256 bits,
   salt `MY_APP_FIXED_SALT_V1` → ikm de 32 B.
3. Cabecera de 40 B: `[0x28]` `[salt de 32 B]` `[prefijo de nonce de 7 B]`.
4. Clave AES = `HKDF-SHA256(ikm, salt=cabecera[1:33],
   info="MY_SECURE_JSON_STREAM_V1", 32 B)`.
5. Segmentos `AES-256-GCM` (sin AAD, tag de 16 B): el **primer** segmento
   de texto cifrado mide **4.056 B** (4.040 de texto plano + tag); los
   demás **4.096 B** (4.080 + tag). La cabecera ocupa los primeros 40 B
   del búfer de 4.096 B del cifrador, por eso el primer segmento es más
   corto; el descifrador lo refleja con `limit(4096-40+1)`. Nonce de
   12 B = prefijo(7) + nº de segmento BE32 + byte de último segmento.

El JSON resultante trae `Version`, `Message`, `Servers`, `Networks` y
`setOpenVPN`.

**Campos `ED:...` (Base32):** `ServerIP`, `Username`, `Password`,
`UDPConfig`, `setOpenVPN` y cualquier otro valor de texto con ese
prefijo se decodifican a UTF-8 en su lugar. El usuario y la contraseña
se devuelven tal como los guarda la app (incluidas las comillas simples
literales: `'IElsIAlN'` / `'lSIelRIvIcIE'`).

Otras URLs de la app (no son el catálogo):
- `GET https://e-san-vpn.in.net/WarnApplication/warn.json` — aviso de
  actualización (diálogo; `Boolean` false el 2026-11-13).
- `https://e-san-vpn.in.net/` — base (`MainDetail.a()`; sin uso en el dex).
- `MainDetail.b()` devuelve el token `Bs3PI5e1Olf5Me8E9Vc7bP1oUhS0eZ`
  (sus primeros 16 B son la clave XXTEA del `profile.json` antiguo,
  no del catálogo).

## Estado en vivo (2026-11-13, verificado con `E_SAN_VPN.py --url`)

- HTTP 200, 26.996 B; descifrado completo en ~3 s en Python puro.
- Catálogo: **versión 36.6**, **15 servidores** (todos de Tailandia,
  flag `th`, sin marca de free/premium en el catálogo): 5 UDP
  (`udp1-5.e-san-dns.com`, con `UDPConfig` Hysteria2: `auth_str`
  `esan:esan`, `obfs` `esan`, 10/20 Mbps, socks5 `127.0.0.1:1080`,
  http `127.0.0.1:8989`) y 10 OpenVPN (`thailand1-10.e-san-dns.com`,
  TCP 1194, mismo usuario/contraseña en los 10).
- **5 redes** (3G, 4G, 5G, Default, WiFi), protocolo OVPN, con `Payload`
  vacío en las 5: **0 payloads HTTP** (son perfiles de red, no payloads).
- `setOpenVPN` es una configuración de cliente OpenVPN (2.074 B
  decodificados, con el certificado CA de E-SAN VPN).

## Archivos guardados

- `profile.json` (formato antiguo): `Base64(XXTEA(JSON))` con clave =
  primeros 16 B del token y delta `0x2E0BA747`. Lo descifra
  `E_SAN_VPN_archivos.py`, con la migración de claves que hace
  `MainActivity.onCreate` (`Name`→`ServerName`, `Flag`→`ServerFlag`,
  `SSLPort`→`OpenVPNSSLPort` y `SSHSSLPort`, `ServerDNS`→`ServerIP`;
  en Profiles: `Name`→`PayloadName`, `Flag`→`PayloadFlag`). La app
  borra este archivo tras migrarlo, así que solo existe en
  instalaciones antiguas o respaldos.
- `profile.enc` (formato actual, `du0.a`): el JSON descifrado, cifrado
  con Tink StreamingAead y una clave propia del dispositivo
  (EncryptedSharedPreferences + Android Keystore). **No se puede
  descifrar sin conexión**; `E_SAN_VPN_archivos.py` lo detecta y lo
  informa como `PROFILE_ENC_DEVICE_KEY`, sin inventar servidores.

La app no tiene formato de perfil importable por intent (su
`MainActivity` solo declara MAIN/LAUNCHER), no tiene esquema de texto
propio (no hay `esan://`) y no exporta perfiles. No hay `.sks`.

## Uso

```bash
python3 E_SAN_VPN.py --url                      # en vivo (imprime JSON)
python3 E_SAN_VPN.py --url -o catalogo.json      # en vivo, guarda JSON
python3 E_SAN_VPN.py --file e-san-vpn.json       # cuerpo Base64 guardado
python3 E_SAN_VPN.py --self-test                # recurso sintético
python3 E_SAN_VPN_archivos.py profile.json       # perfil antiguo
python3 E_SAN_VPN_archivos.py --self-test        # perfil sintético
```

`--self-test` del catálogo usa `e-san-vpn-test.json`, un catálogo
sintético cifrado con la misma contraseña, salt y datos asociados que
el real (servidores ficticios `*.test.example.com`); no contiene
credenciales reales. El descifrado en vivo se verificó aparte con
`--url` el 2026-11-13 (versión 36.6, 15 servidores, 5 redes).

## Archivos

- `E_SAN_VPN.py` — descifrador del catálogo (SHA-256
  `d059b8ebae7a6c333dc78b72c953c364b7d542d0dfa243b1571b89c486bb334c`).
- `E_SAN_VPN_archivos.py` — descifrador de `profile.json` antiguo
  (SHA-256 `287e139e10f62b2d2ee0328a8ccbf77e8cb9fa5bd823c189898116d145476d6f`).
- `E_SAN_VPN.png` — icono 512×512.
- `e-san-vpn-test.json` — catálogo sintético para `--self-test`.

## Pendiente

- Confirmación de extremo a extremo con un `profile.json` real de un
  teléfono (instalación antigua o respaldo): el descifrado XXTEA +
  migración está verificado solo con round-trip sintético.
- Un `profile.enc` real no se puede abrir sin conexión (clave del
  dispositivo en Keystore); el catálogo en vivo (`--url`) es la vía
  para obtener los servidores actuales.
- Si el servidor rota la contraseña `key_secured` o cambia el formato
  del sobre, el script informará `LIVE_DECRYPT_FAILED` (no inventa
  servidores); habría que re-analizar `jc0`/`p5` en el APK nuevo.

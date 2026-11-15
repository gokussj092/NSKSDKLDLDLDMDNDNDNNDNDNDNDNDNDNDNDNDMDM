# DocNet VPN — catálogo para SP-DECODE

- **App:** DocNet VPN
- **Paquete:** `tech.docnet.docnetvpn`
- **Versión:** 6.1.4 (versionCode 314, minSdk 25, targetSdk 36)
- **Fuente:** XAPK de APKPure en la versión de Google Play (134.072.876 B,
  SHA-256 `a20339c3bc46e59b55529669ab200ceafd2030b663a2ec4065cfce67f6b24076`)
- **Repo SP-DECODE:** sin cobertura previa (86 carpetas en
  `decoders/Python/apps/`, nada para este paquete).

## Catálogo (público, funciona en vivo)

```
GET https://docnet.tech/configs/
```

Petición exacta de la app (Dart `http`): GET plano, sin headers propios
ni autenticación. Responde HTTP 200 con un JSON: una lista de configs.

**Prueba en vivo (2026-11-13, `DocNet_VPN.py --url`):**

| Dato | Valor |
|---|---|
| Total de configs | **591** (574 gratis, 17 premium) |
| Tipos | http **371**, tls **220** |
| Operadores top | VIVO BR 119, TIM BR 114, Outros 77, KSA 43, CLARO BR 34 |
| CDN top | DIRECT 139, Cloudfront 128, cloudflare 102, direct 88, Cloudflare 78 |

Cada config trae metadatos completos (`id`, `name`, `type`, `default`,
`cdnName`, `noteMsg`, `operator`, `sshServerIP`, `SshServerPORT`,
`SshServerName`, `Ssh`, `cdn`, `multiproxy`, `notes`, `downloaded`,
`cdnNumber`, `testPriority`, `onlines`, `votesPositives`,
`votesNegatives`, `forpremium`) y el campo `config` con el payload.

**El catálogo de metadatos es estable entre descargas** (mismas 586
claves únicas nombre/tipo/operador y mismo orden), pero **los blobs
`config` cambian en cada petición (0/591 idénticos entre dos descargas)**:
el servidor re-cifra cada blob con un IV/nonce aleatorio nuevo.

## El payload `config`: cifrado AES-256, clave NO recuperada offline

La app dice en su propio texto que los configs van "encriptados com
AES-256". El descifrado **no** se pudo recuperar offline en la 6.1.4:

- La app es Flutter (Dart AOT, `libapp.so`) + núcleo Go
  (`libdocksocks.so`, xray/tun2socks). En Dart no hay paquete de cifrado
  (no hay `encrypt`/PointyCastle); solo `package:crypto` (SHA-256/HMAC)
  y el AES del paquete `archive` (solo para entradas ZIP, `_decodeAes`
  de `ZipFile`). El núcleo Go es solo el motor del túnel; recibe los
  campos ya descifrados desde Dart.
- La clave NO es una cadena literal del binario ni se deriva de ninguna
  cadena embebida con los KDF/modos estándar probados (SHA-256,
  PBKDF2-HMAC-SHA1 1000 iters, raw; CTR/CFB/OFB/CBC/GCM/ChaCha20-Poly1305;
  layouts con IV/nonce/salt al inicio y WinZip AES; ~1.400 contraseñas
  candidatas, verificación por texto claro conocido `{"name":"` y por
  HMAC/verify).
- Estructura de los blobs: longitudes decodificadas siempre múltiplo de
  4 (591/591), nunca múltiplo de 16 → modo stream (CTR/CFB/OFB) o AEAD,
  NO CBC con PKCS7. El texto claro es un JSON como
  `{"name":...,"type":"HTTP","payload":"GET / HTTP/1.1[crlf]...",
  "cdnName":"direct","isTls":false,"isQuic":false,"description":...}`
  (muestra embebida en `libapp.so`).
- El endpoint de servidores `/api/*` (`api.docnet.tech`) exige el header
  `X-API-Key` y la clave tampoco se recuperó offline; los JWT de ejemplo
  embebidos en `libapp.so` están caducados (exp sep/oct 2025).

**Para abrir los payloads hace falta** una captura en vivo en un teléfono
con la app oficial (proxy/Frida durante la descarga del catálogo) o la
clave autorizada del emisor. El script entrega el catálogo completo de
metadatos + el blob cifrado de cada config y marca cada payload como
`ENCRYPTED_AES256_PENDING` en lugar de inventar un descifrado.

## Servidores (API, bloqueada por clave)

- Host: `https://api.docnet.tech`
- Rutas: `/api/appconfig`, `/api/cdn-compatibility/admin`, `/api/configs`,
  `/api/servidores`, `/authentication/anonymous/activate`,
  `/authentication/anonymous/validate`, `/resetpremiumuser/`
- Todas las `/api/*` devuelven 401
  `{"success":false,"error":"Unauthorized","message":"API Key inválida ou
  ausente. Use o header X-API-Key."}` sin esa clave.
- `/health` responde 200 (`"DocNET API Worker está funcionando"`,
  base de datos conectada) — el backend es un Cloudflare Worker.
- Muestra de servidor embebida en `libapp.so` (nov 2024): esquema
  `{Domain, DnsttDomain, Country, City, State, Ipv4, Ipv6, PortHTTP 80,
  PortTLS 443, PortQUIC 0, PortDNSTT 53, Flag, CdnName, Premium, Tls,
  Quic, Http, Dnstt, Cdn, Usage, LastPing, OnlineUsers, Capacity,
  CdnNumber, Cdns:[{Key, Value:[...]}]}`.

## Formatos de archivo

La app **no tiene formato propio importable**: no hay `ACTION_VIEW` para
archivos ni extensión propia en el manifest. No hay `.sks`. Por eso no
hay script `DocNet_VPN_archivos.py`.

## Esquemas de texto (deep links)

Verificados en el `AndroidManifest.xml` de ESTE apk (MainActivity,
`ACTION_VIEW` + `BROWSABLE`):

- `docnet://docnet.tech`
- `https://import.docnet.tech`

Son enlaces de importación de config (existe el diálogo de importación
en la app: "Falha ao importar a configuracao"). El formato exacto del
payload del enlace NO está verificado: hace falta un enlace real
generado por la app.

## Archivos

| Archivo | SHA-256 | Notas |
|---|---|---|
| `DocNet_VPN.py` | `a0f8cf2621d5624a764851ab97b5d102c9871c903dcf5bdd4ecb07105371a983` | Catálogo: `decode()` + `run()` + CLI `--url/--file/--self-test/-o/--summary` |
| `DocNet_VPN.png` | `16f2fc0f5bb2a02e56ae8fce31c99dead4805bdedcd9cd49a6cee8110f85a81e` | Icono 512×512 (del `icon.png` del XAPK) |
| `docnet_configs_sample.json` | `a27690e5361a39a2dfe61028a77469770d1efbf43a653b71639cd734e8a317fe` | Muestra de 5 configs reales para `--self-test` |
| `README.md` | — | Este archivo |

## Uso

```bash
python3 DocNet_VPN.py --url                 # catalogo en vivo
python3 DocNet_VPN.py --url --summary       # resumen corto
python3 DocNet_VPN.py --url -o out.json     # guardar resultado JSON
python3 DocNet_VPN.py --file configs.json   # catalogo local
python3 DocNet_VPN.py --self-test           # 7/7, sin red
```

## Notas de red (para quien ejecute el script)

- El servidor bloquea el User-Agent por defecto de Python-urllib
  (HTTP 403); el script envía el UA de Dart (`Dart/3.4 (dart:io)`),
  como la app.
- El servidor a veces corta la descarga antes de enviar el cuerpo
  completo; el script usa `http.client` directo (nunca urllib, que
  añade `Connection: close`), reintenta hasta 6 veces y solo acepta el
  cuerpo completo según `Content-Length` (patrón de RoVPN/Fat Tunnel).
  El proxy saliente se lee del entorno en cada llamada (las
  credenciales rotan).

## Pendiente

1. **La clave AES-256 del payload `config`** (o una captura en vivo del
   catálogo descifrado en un teléfono con la app oficial). Con ella,
   `DocNet_VPN.py` se completa sin cambiar la interfaz.
2. **La `X-API-Key`** de `api.docnet.tech` (para el endpoint de
   servidores `/api/servidores` y `/api/configs`).
3. **Un enlace real** `docnet://docnet.tech` o
   `https://import.docnet.tech` generado por la app, para verificar el
   formato exacto de importación por deep link.
4. Un `config` ya descifrado de ejemplo (JSON con `name/type/payload/
   cdnName/isTls/isQuic/description`) para validar el descifrador
   cuando se tenga la clave.

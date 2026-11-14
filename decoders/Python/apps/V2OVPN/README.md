# V2OVPN 2.2.3 — catálogo y archivos (SP-DECODE)

App: **V2OVPN**, package `com.v2rayservice.v2ovpn`, version 2.2.3,
versionCode 63, minSdk 32. Es la versión pública de Google Play
(2.2.3); el XAPK se descargó de APKPure porque APKMirror no tenía
listado. SHA-256 del XAPK:
`96e34c974a3db687a5c61460419c4ef5f3f6567be611820f1d82ceba48ff0de4`.
Es un fork de v2rayNG. **Sin cobertura previa en el repo de
SP-DECODE** (86 carpetas revisadas en la rama
`feat/nuevas-integraciones`; V2ray_Tunnel_Plus es otra app).

## Catálogo

**URL:** `GET https://iovpn.me/app/config/rooojshsh727272h3n.php`
(GET plano con User-Agent `okhttp/4.12.0`, sin autenticación; el
User-Agent por defecto de Python-urllib recibe 403 de Cloudflare.)

El cuerpo es una línea Base64 (54.128 B en vivo el 2026-11-13) que
decodifica a un flujo **Google Tink StreamingAead /
AesGcmHkdfStreaming** (mismo framework que RoVPN y E-SAN VPN, tanda 7):

- byte 0 = longitud de la cabecera (40); bytes 1..32 = salt (HKDF);
  bytes 33..39 = prefijo de nonce de 7 B; resto = segmentos
  AES-256-GCM sin AAD.
- IKM = PBKDF2-HmacSHA256(clave `key_secured`, salt
  `MY_APP_FIXED_SALT_V1`, 100.000 iteraciones, 32 B);
  `key_secured = UED%tS^yeUXI{C=,i_Y#J5+Vb}uFnAz8;}7)n8)PaTOe97=.3%`
  (constante de la app, guardada en EncryptedSharedPreferences junto
  a `key_url`; es **idéntica a la de RoVPN** — mismo proveedor).
- clave = HKDF-SHA256(IKM, salt de la cabecera, info
  `MY_SECURE_JSON_STREAM_V1`, 32 B).
- Segmentos: el primero cifrado 4.056 B (4.040 texto + 16 tag), los
  siguientes 4.096 B (4.080 + 16), el último el resto; nonce =
  prefijo(7) || BE32(índice) || (0x01 si es el último, 0x00 si no).
  Todos los tags se verifican.

El texto plano es un JSON `{Version, Message, Servers[], Networks[],
setOpenVPN}`. Casi todos los campos sensibles llevan el prefijo
`ED:` y son Base32 del valor en claro (ServerIP, Username, Password,
Cloudfront, UDPConfig, NameServer, PublicKey, ServerDNS, SquidProxy,
setOpenVPN, Payload). Este script los decodifica.

**Prueba en vivo (2026-11-13, con `--url`):** HTTP 200, 54.128 B,
**Version 46.1**, Message " Up", **12 servidores** (todos libres, sin
marca premium) y **23 redes (payloads)**. El cuerpo es **idéntico al
de RoVPN** (mismo SHA-256): ambas apps comparten el mismo catálogo.
Descifrado verificado dos veces: con las clases de la propia app en
la JVM y con el AES-256-GCM puro en stdlib de este script
(byte a byte iguales).

**Incidencia de red:** el endpoint responde chunked sin
Content-Length y cierra sin el chunk terminal `0\r\n\r\n`; urllib
trunca la respuesta a 18.791 B (el primer chunk) a través del proxy
de esta máquina. El script usa `http.client` con un túnel CONNECT
explícito al proxy y nunca envía `Connection: close`; un cuerpo
truncado se reintenta con un GET nuevo (hasta 4 intentos) y los tags
GCM prueban que el cuerpo está completo. **No usar Range:** el
servidor devuelve otra versión (40.975 B) para peticiones con Range.

## Endpoints secundarios (verificados en vivo)

- `GET https://iovpn.me/app/v2ovpn/ping.json` → 200, 4 servidores TH
  (g18/g7/g5/g4.drm.ac.th, puerto 82). Esos 4 hosts ya no responden a
  `:82/server/online_app.json` (respuesta vacía).
- `GET http://<host-del-catalogo>:82/server/online_app.json` →
  `[{"onlines":"78","limite":"150"}]` (verificado con d1.rovpn.uk:
  80/150; f1.rovpn.uk: 127/250). `--online <host>` lo consulta.
- `GET https://iovpn.me/app/config/hg77hsushshss.php` (de
  libapi-v2ovpn.so, MainDetail.a()) → **404**: endpoint viejo, muerto,
  no se usa. MainDetail.c() (`.../v2ovpn/ping.json`) tampoco se usa
  desde Java. Solo MainDetail.b() tiene llamador (MainActivity.onCreate).

## Archivos de configuración

**profile.json** (getFilesDir()): el catálogo guardado con una
**segunda capa** (MainActivity.onCreate; verificada contra las clases
de la propia app en la JVM: `Li61.g` = Base64, `Li61.h` = XXTEA):
flujo Tink → cadena Base64 → **XXTEA modificado** (delta 0x2E0BA747,
clave = primeros 16 B UTF-8 de MainDetail.b() =
`aZ%RU%itRMB^8&Ue`, longitud como palabra extra) → JSON con nombres
**antiguos**. La app migra los nombres al importarlo, lo guarda como
profile.enc y **borra** profile.json. Migración (verificada clave por
clave contra `er2.p` en onCreate):
- nivel superior: `Profiles` → `Networks` (si no hay `Networks`);
- Servers: `Name`→`ServerName`, `Flag`→`ServerFlag`,
  `SSLPort`→`OpenVPNSSLPort` **y** `SSHSSLPort` (mismo valor),
  `ServerDNS` por defecto = `ServerIP` si falta,
  `OvpnCertificate`→`setOpenVPN`, `AutoLogIn`/`MultiCert`:
  booleano → cadena `"true"`/`"false"`;
- Networks: `Name`→`PayloadName`, `Flag`→`PayloadFlag`,
  `Info`→`PayloadInfo`, `ServerDNS` por defecto `""`,
  `UseDefProxy`: booleano → cadena.

**Verificación de extremo a extremo:** un profile.json sintético de
doble capa construido con este script fue abierto por el pipeline
completo de la propia app en la JVM (Tink → Li61.g → Li61.h) y
recuperó el JSON antiguo **byte a byte**; y este decodificador lo
abre con la migración correcta (`--self-test` 17/17). Falta un
profile.json real de un teléfono para la confirmación final.

**profile.enc**: flujo Tink con una clave del keyset de la app
(Lm11), no reproducible sin el dispositivo. El script lo detecta y
lo informa como pendiente (`PROFILE_ENC_KEY`), sin inventar un
descifrado.

**config.json / proxies.json**: JSON plano que la app genera; se
devuelven tal cual. No hay `.sks`. No hay formato propio de archivo
exportable más allá de profile.json / profile.enc (la app no declara
intent-filter VIEW para archivos).

## Enlaces de texto

**Ninguno propio**: no hay esquema `v2ovpn://` en el manifiesto ni
en el DEX. Solo los estándar vmess:// / vless:// / trojan:// / ss://,
que SP-DECODE ya cubre.

## Uso

```sh
python3 V2OVPN.py --url            # catálogo en vivo (por defecto)
python3 V2OVPN.py --url <otra-url> # otro endpoint Tink igual
python3 V2OVPN.py --ping           # lista ping.json (4 servidores TH)
python3 V2OVPN.py --online d1.rovpn.uk   # onlines/límite de un servidor
python3 V2OVPN.py archivo.b64      # cuerpo cifrado guardado
python3 V2OVPN.py --self-test      # 10/10
python3 V2OVPN_archivos.py profile.json   # doble capa Tink+XXTEA
python3 V2OVPN_archivos.py --self-test    # 17/17
```

## Archivos

- `V2OVPN.py` — catálogo (stdlib puro: AES-256-GCM, HKDF, PBKDF2).
- `V2OVPN_archivos.py` — profile.json / profile.enc / JSON plano
  (importa el Tink de V2OVPN.py; XXTEA propio en este archivo).
- `V2OVPN.png` — icono del lanzador 512×512 (el XAPK no trae
  icon.png; extraído de `res/drawable/icon_launcher.png` del APK,
  que ya es 512×512).
- `catalog_sample.b64` — cuerpo vivo cifrado del catálogo (54.128 B,
  v46.1), usado por `--self-test`.

## Pendiente

- Un profile.json real exportado de un teléfono para la confirmación
  de extremo a extremo (el descifrado de doble capa + migración está
  verificado solo con round-trip sintético y con el pipeline de la
  propia app en la JVM). Un profile.enc real no se puede abrir sin
  el dispositivo (clave del keyset en Keystore).
- Si el proveedor rota `key_secured` o cambia el endpoint, el script
  informará `LIVE_DECRYPT_FAILED` / `DOWNLOAD_FAILED` sin inventar
  servidores.

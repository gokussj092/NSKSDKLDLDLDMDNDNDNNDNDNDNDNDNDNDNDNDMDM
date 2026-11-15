# YLA VPN 1.2.4 — catálogo

Package `com.thuaung.ylavpn`, versionCode 10, versionName 1.2.4,
minSdk 24, targetSdk 36. XAPK de APKPure (APKMirror no tenía listado),
SHA-256 `e389d6e51a2ba038eee749613c7e6e604840d159f32f5a30cdd8803b5cbf6cf4`
(APKPure decía build 24; el manifiesto dice 10 — manda el manifiesto).
App **solo 32 bits** (armeabi-v7a). SP-DECODE no cubría esta app
(sin carpeta en `decoders/Python/apps/`, sin mención en `decoders.json`).

## Método del catálogo

App Flutter (Dart AOT, `libapp.so`) + núcleo Xray Go (`libv2jni.so`).
Panel Laravel en `https://adminpannel.ylavpn.store` (la URL base llega
por Firebase Remote Config; este es el dominio de reserva que trae la
app). Cliente HTTP Dio (`DioClient`).

**1. Registro del dispositivo** — `POST /api/user/init`, JSON:

```json
{"device_id": "<id>", "device_model": "<modelo>", "app_version": "1.2.4"}
```

→ 200:

```json
{"success": true, "is_banned": false,
 "data": {"user_code": "YLA-XXXXXX", "device_id": "...",
          "is_vip": false, "vip_expired_at": null,
          "vip_expired_formatted": "No Active VIP",
          "unread_notifications": 1, "status": 1, "ban_reason": null}}
```

El device_id lo genera la app ("Generated Secure Device ID", clase Dart
con `_generateSecureRandomId`) y se guarda en caché
(`cached_device_id` / `cached_user_init_data`). Cualquier device_id es
aceptado por el registro. Verificado en vivo con un device_id hexadecimal
y con un UUID (user_codes `YLA-BFJHCA`, `YLA-LK6NQS`, `YLA-WIHV1F`).

**2. Catálogo de servidores** — `GET /api/v2ray/list` (solo GET/HEAD):

```
GET /api/v2ray/list?device_id=<id>&signature=<firma>
```

**3. Endpoints abiertos** (GET, sin auth, verificados en vivo):

- `GET /api/app-yla-setting` → ajustes: `app_version` 1.2.4,
  `force_update` 1, Telegram `ylavpnmyanmar`, contacto
  `contact@ylavpn.store`, web `https://ylavpn.store/`, privacidad y
  términos.
- `GET /api/plans` → planes VIP en MMK: 1 mes 5.000, 3 meses 15.000,
  6 meses 30.000 (device_limit 1).

**4. Notificaciones** (POST, JSON, solo device_id, verificado en vivo):

- `POST /api/user/notifications` → `{"success": true,
  "unread_count": 1, "data": [...]}`.
- `POST /api/user/notifications/read` → `{"success": true, "message": ...}`.

## La firma: PENDIENTE (bloqueo honesto)

La app trae la constante `YLA_VPN_SECURE_SALT_2026` en `libapp.so` y
una función `_hashWithSha256` (misma clase Dart que
`_generateSecureRandomId` y `_loadCachedUserData`). La firma se calcula
en el cliente con SHA-256, pero la fórmula exacta **no pudo
determinarse**:

- ~280 combinaciones probadas en vivo, todas HTTP 403
  `{"success": false, "error": "Unauthorized access or invalid signature"}`:
  sha256 / HMAC-SHA256 / MD5; órdenes de device_id, user_code y sal;
  separadores `''`, `|`, `:`, `-`, `_`; con y sin timestamp (segundos y
  milisegundos); como parámetro `?signature`, `?sign`, `?sig` y como
  cabeceras `X-Signature` / `Authorization: Bearer`; con device_id
  hexadecimal y con UUID.
- El binario Dart AOT no se pudo desensamblar hasta la fórmula: el pool
  de objetos se accede con `ldr Rt, [r7, r0, lsl #2]` (r7 = pool
  pointer), pero su codificación de offsets no se resolvió (no hay
  secciones de reubicación; los offsets relativos probados no mapean
  las constantes de la sal ni de `/api/v2ray/list`).

El script usa como intento documentado
`signature = sha256_hex(device_id + SALT)` y lo marca como NO
VERIFICADO. `--url` se detiene con `LIVE_AUTH_FAILED` (salida 2) y no
inventa servidores. Cuando se conozca la fórmula, solo hay que corregir
`compute_signature()`; registro, descarga y parseo ya están verificados.

Para desbloquearlo hace falta una de estas dos cosas:

1. Una captura en vivo en un teléfono con la app oficial (proxy o
   Frida durante una actualización de servidores): la petición real
   muestra la firma y con ella se deduce la fórmula.
2. Completar el análisis del binario Dart AOT (resolver el pool de
   objetos y desensamblar la función que construye la petición).

## Estado en vivo (2026-11-13)

- `POST /api/user/init` → 200, user_code emitido.
- `GET /api/app-yla-setting` → 200. `GET /api/plans` → 200.
- `POST /api/user/notifications` → 200, `unread_count` 1.
- `GET /api/v2ray/list` → **403** siempre ("Unauthorized access or
  invalid signature"). Versión del catálogo, servidores y payloads:
  **indeterminados** (nunca se obtuvo una respuesta autenticada).

## Esquema esperado del catálogo

No confirmado en vivo. Nombres de campo tomados del binario Dart
(modelo V2Ray de la app): `address`, `port`, `protocol`
(vmess/vless/trojan/shadowsocks), `security`, `network`, `path`,
`host`, `sni`, `tls`, `flow`, `fingerprint`, `reality`, `fragment`,
`mux`, `remark`, `level`, `location`, `speed`, `country_code`, `flag`,
`is_vip`, `is_premium`, `is_free`, `active`, `config`, `uuid`,
`password`, `method`. `decode()` es tolerante al esquema: busca la
lista en `data` / `servers` / `list` o en la raíz, conserva cada
registro completo y resume servidores, gratuitos, VIP y payloads
(cada servidor ES su payload: su config V2Ray).

## Archivos y textos

- **Sin formato propio de archivo**: el manifiesto solo tiene
  MAIN/LAUNCHER en MainActivity; no hay intent-filter VIEW ni
  asociación de extensiones. La importación es por portapapeles
  ("Paste your config string here...", "No valid config found in
  Clipboard!") y por escaneo QR (mobile_scanner). Por eso no hay
  `YLA_VPN_archivos.py`.
- **Sin esquema URI propio**: solo los enlaces estándar vmess://,
  vless://, trojan:// y ss://, que SP-DECODE ya cubre. Sin `.sks`.
- Librerías nativas (todas en `config.armeabi_v7a.apk`; la base no
  tiene `.so`): `libapp.so` (Dart AOT), `libflutter.so`,
  `libv2jni.so` (núcleo Xray Go, 32 MB), `libbarhopper_v3.so`,
  `libdartjni.so`, `libdatastore_shared_counter.so`,
  `libimage_processing_util_jni.so`, `libsurface_util_jni.so`,
  `libtun2socks.so`. El catálogo es Dart puro (Dio); el Go solo es el
  núcleo VPN.

## Uso

```
python3 YLA_VPN.py --url [--device-id ID] [-o catalogo.json]
python3 YLA_VPN.py --init [--device-id ID]
python3 YLA_VPN.py --settings | --plans
python3 YLA_VPN.py --notifications --device-id ID
python3 YLA_VPN.py catalogo.json
python3 YLA_VPN.py --stdin < catalogo.json
python3 YLA_VPN.py --self-test
```

## Pendiente

- La fórmula de la firma (ver arriba): con ella, `--url` descargará el
  catálogo sin más cambios.
- Un catálogo real (JSON de `/api/v2ray/list`) para confirmar el esquema
  de servidores de extremo a extremo.

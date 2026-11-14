# VertexSnipher 0.1.46 (codes.juanscript.vertexsnipher)

**Catálogo BLOQUEADO por identidad de dispositivo + Play Integrity (honesto).
Decodificador `snipher://` COMPLETO y verificado por ida y vuelta.**

App: VertexSnipher, `codes.juanscript.vertexsnipher`, 0.1.46 / build 46,
minSdk 32, targetSdk 36. Versión pública de Google Play, descargada de
APKPure (APKMirror no tenía listado; XAPK SHA-256
`66b1a7af…029a`, 61.479.734 B). Sin cobertura previa en el repo de SP-DECODE
(86 carpetas; `VIP_Snipher_Pro` es otra app, `dev.renz.soft.vipsnipherpro`).

Librerías nativas (todas en `config.arm64_v8a.apk`; el base no trae .so):
`libxray.so`, `libhysteria1.so`, `libhysteria2.so`, `libdnsttclient.so`,
`libjuanssh.so`, `libovpnjuan.so`, `libhev-socks5-tunnel.so`,
`libdatastore_shared_counter.so`. El catálogo es Java/Kotlin puro (OkHttp).

## Catálogo — bloqueado (no se inventa nada)

Endpoints (m61.k, fh3.e, n61.j, q70.m, AnnouncementInbox.d):

| Endpoint | Qué trae |
|---|---|
| `GET https://www.juanscript.codes/api/servers?users=76` | Servidores: `{id, status, country, domain, ip, cert, ovpn_online, cloudfront, fastly, cloudrun, vless, vmess, trojan, shadowsocks/ss, udp_version, udpv1/udp_v1, udpv2/udp_v2, obfs_value, ns_domain, public_key}` |
| `GET .../api/prebuilt-configs?users=76&include_global=0` | Perfiles prebuilt: `{id, name, mode, country_code, owned_by, ...todos los campos del perfil}` |
| `GET .../api/prebuilt-xrays?users=76&include_global=0` | Xray prebuilt: `{id, name, type, mode, transport, address, port, ws_host, path, xhttp_mode, allow_insecure, alpn[], sni, country_code, owned_by}` |
| `GET .../api/openvpn-files` | Lista de archivos .ovpn del servidor |
| `GET .../api/app-sync?users=76` | Anuncios (con ETag / If-None-Match) |

Petición exacta (todas las rutas): `User-Agent: Vertex/0.1.46`,
`Accept: application/json` (openvpn-files:
`application/json, application/x-openvpn-profile`),
`X-App-Package: codes.juanscript.vertexsnipher`,
`X-App-Version-Code: 46`, `X-App-Version-Name: 0.1.46`. Además
`X-Content-User-Id: 76` en prebuilt-* y app-sync. Respuesta JSON en
claro, sin cifrar: `{"ok": true, "data": [...]}`. La app guarda el
catálogo en SharedPreferences (`server_cache_user_76` /
`prebuilt_config_cache_user_76`); el APK no trae catálogo incluido.

Puerta de identidad (ab0.b + g52.a), en todas las rutas:

- `X-App-Variant: vertexsnipher`
- `X-Report-Device-Id`: ANDROID_ID del dispositivo
- `X-Report-Installation-Id`: UUID de instalación de la app
- `X-Reward-Device-Id`: mismo ANDROID_ID
- `X-Play-Integrity-Session`: token de sesión de Google Play Integrity
  (SharedPreferences `play_integrity_session`; lo emite el
  IntegrityManager en el dispositivo, ligado a la app, al dispositivo y
  al nonce del desafío; caduca en minutos).

Pruebas en vivo (2026-11-13, con la petición exacta):

- Sin cabeceras de dispositivo → **HTTP 403**
  `{"ok": false, "error": "device_identity_required", "message": "Update
  the app and verify this device to continue."}`
- Con ANDROID_ID + installation-id fabricados (sin sesión de
  integridad) → **HTTP 403** `{"ok": false, "error":
  "play_integrity_required", "message": "Install or update the official
  app from Google Play to continue."}`

`VertexSnipher.py --url` reproduce la petición exacta y se detiene con
`VERTEX_DEVICE_IDENTITY_REQUIRED` o `VERTEX_INTEGRITY_REQUIRED`
(salida 2). Versión, servidores y payloads: **indeterminados** — el
servidor no devuelve el catálogo sin un dispositivo verificado.

Para abrir el catálogo hace falta un teléfono con la app oficial
instalada desde Google Play y verificada, pasando
`--device-id` (ANDROID_ID), `--installation-id` y
`--integrity-session` (token vigente). También sirve un `servers_json`
o `configs` guardado por la app en el teléfono (SharedPreferences),
que se abre con `--file` (también acepta un array JSON directo).

No hay espejo público del catálogo (sin GitHub raw, Pastebin ni
similar en el DEX) ni URL alternativa.

## Códigos `snipher://` — COMPLETO

La app no tiene formato propio de archivo: los perfiles se comparten por
código de texto `snipher://` (pegado en la app; no es deep link
registrado en el manifiesto). `VertexSnipher_archivos.py` lo descifra
(y lo construye para pruebas):

```
snipher://<2:|3:><base64url_sin_relleno(sobre)>.<sha256_hex(base64)[:16]>
sobre = BE32(16) || salt[16] || BE32(12) || nonce[12] || ct || tag(16)
clave = PBKDF2-HmacSHA256(contraseña, salt, 120000 iter, 32 B)
  v2: "rdxiNA3WXwfRAjdm@092898yue"
  v3: "rdxiNA3WXwfRAjdm@092898yue|device-lock-v3"
texto plano = GZIP(JSON del perfil)
```

Formato heredado (sin `2:`/`3:`):
`snipher://<base64url(base64_std(sobre))>.<sha512_hex(base64)>`, texto
plano = JSON en claro (o GZIP si trae el magic).

`--self-test` 10/10: ida y vuelta v2, v3 y heredado, checksum alterado
rechazado, sobre alterado rechazado, prefijo inválido rechazado,
vector NIST AES-256-GCM. `mobivpn://message/<id>` es solo un enlace
interno de notificaciones, no un formato de importación. Los `.ovpn`
son OpenVPN estándar (SP-DECODE ya los cubre).

## Uso

```sh
python3 VertexSnipher.py --url            # servidores (bloqueado sin dispositivo verificado)
python3 VertexSnipher.py --url prebuilt-configs
python3 VertexSnipher.py --url --device-id <ANDROID_ID> --installation-id <UUID> --integrity-session <TOKEN>
python3 VertexSnipher.py --file servers_guardados.json --summary
python3 VertexSnipher.py --self-test      # 11/11
python3 VertexSnipher_archivos.py "snipher://2:...."   # descifra un código
python3 VertexSnipher_archivos.py --encode perfil.json --version 3
python3 VertexSnipher_archivos.py --self-test          # 10/10
```

## Pendiente

1. Un dispositivo verificado con la app oficial (o sus valores
   `--device-id` / `--installation-id` / `--integrity-session`, o un
   `servers_json` guardado) para descargar el catálogo real y cerrar
   versión/servidores/payloads.
2. Un código `snipher://` real de un teléfono para la confirmación de
   extremo a extremo (el formato está verificado por ida y vuelta
   sintético contra el código exacto del DEX, pero sin muestra real).

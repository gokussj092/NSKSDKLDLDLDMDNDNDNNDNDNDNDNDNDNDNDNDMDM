# XJ VPN 1.9.7 (net.xj.vpn) — tanda 10b

App oficial del backend XJ (el mismo que usa CATNET VPN, tanda 6:
hosts `pussyvpn.com/xjvpn` y `xjdev.net`, cabeceras `X-XJ-App-Key`).
Verificado en ESTE APK: no se reutilizó nada de CATNET sin comprobarlo.

- APK: `XJ_VPN_1.9.7_APKPure.xapk` (44.195.373 B, SHA-256
  `9d5fd62e…688aa`, coincide con el publicado por APKPure), build 99,
  minSdk 26. Base + split arm64 (todas las .so están en el split:
  `libapp.so` Flutter/Dart, `libflutter.so`, `libgojni.so`,
  `libhev-socks5-tunnel.so`, `libhysteria.so`, `libovpncli.so`,
  `libxjovpntune.so`, `libxray.so`) + splits en/fr/hdpi.
- Repo SP-DECODE (rama `feat/nuevas-integraciones`, revisado
  2026-11-14): NO tiene proveedor XJ (solo `CATNET_VPN` en
  `decoders/Python/apps/`). Cobertura nueva.
- Icono: `XJ_VPN.png` 512×512, del `ic_launcher.png` xxxhdpi del APK
  (el XAPK no trae `icon.png`).

## Catálogo en vivo: BLOQUEADO por Play Integrity (honesto, no inventado)

`XJ_VPN.py` replica la petición exacta de la app (método GET, URL,
cabeceras del interceptor OkHttp, UA `okhttp/4.12.0`):

- Base `https://onlinetoolx.com/xjvpn/`, `APP_KEY xj_vpn`,
  paquete `net.xj.vpn`, version code 99.
- Preflight `GET mobile/public/app-update?app_key=xj_vpn&current_version_code=99`
  → HTTP 200: `maintenance false`, `integrity_required true`,
  `integrity_challenge` JWT nuevo en cada llamada
  (`{app: xj_vpn, pkg: net.xj.vpn, ver: 99, nonce, exp}`).
  Ojo: el preflight dice `latest_version_code 66 / 1.6.2`, dato
  obsoleto del servidor (la app es 1.9.7/99).
- Endpoints: `mobile/public/servers`, `payloads`, `xray_payloads`,
  `v2ray-configs`, `accounts`. Los 5 devuelven el mismo
  **HTTP 403, 242 B**: `{"success":false,"modified_app":true,
  "integrity_rejected":false,"message":"This app installation is not
  verified. Install the official XJ app from Google Play."}`

El servidor exige un veredicto válido de Play Integrity (token que
solo Google Play Integrity emite en un dispositivo real con la app
genuina de Play). Ningún script offline puede producirlo. El
resultado es `LIVE_BLOCKED_BY_INTEGRITY` (salida 1 en `--url`),
igual que el bloqueo que CATNET sufrió en la tanda 6, salvo que
allí el endpoint de servidores sí pasaba en 1.2.7 y aquí no pasa
ninguno. Lo que lo desbloquearía: captura en vivo en un dispositivo
con la app instalada desde Play, o un `.xj` / `xjdev://` real
exportado desde la app.

```bash
python3 XJ_VPN.py --self-test   # sin red
python3 XJ_VPN.py --url          # preflight + 5 endpoints en vivo
python3 XJ_VPN.py --url mobile/public/servers   # un solo recurso
```

## Archivos .xj y enlaces de texto: decodificadores completos

`XJ_VPN_archivos.py` (stdlib puro: AES-256-GCM en Python puro,
PBKDF2 con `hashlib`, XZ con `lzma`, GZIP con `gzip`). Cripto común:
PBKDF2-HmacSHA256, 120.000 iteraciones, AES-256-GCM tag 128,
salt 16 B, nonce 12 B. Las passphrases fijas son constantes públicas
de la app, no credenciales de cuenta.

| Formato | Clave / sobre | Contenido |
|---|---|---|
| Archivo `.xj` (`xj-config-v1`) | contraseña del usuario (o sin cifrar si `locked=false`) | JSON sobre `{"data","locked","format","iv","salt"}` → `{"configName","server": ServerDto,"configLocked"}` |
| Enlace `xj://` (`xj-link-v1`) | fija `xj-vpn-portable-link-v1` | Base64url del JSON del sobre → mismo payload |
| Enlace `xjgcp://` (v1) | fija `xj-vpn-gcp-host-update-v1` | Binario `[ver=1, salt16, nonce12, GCM]` Base64url sin padding → XZ → `{"createdAt","hosts":[HostUpdate]}` |
| Enlace `xjdev://` (v2) / `xjvpn://` (v1 legacy) | fija `xj-vpn-offline-update-v1` | Binario `[ver, salt16, nonce12, GCM]` → v2 XZ, v1 GZIP → `{"createdAt","servers":[ServerDto],"payloads":[PublicPayloadDto]}` |
| Sobre `xj-local-v1` / `xj-runtime-v1` | fija `xj-vpn-portable-link-v1` | Lista de ServerDto / texto plano, mismo sobre JSON |

Esquemas declarados en el manifest (MainActivity, ACTION_VIEW):
`xjvpn://`, `xjdev://`, `xjgcp://`, `xj://`; archivos `.xj`
(mime `application/x-xjvpn`, `.*\.xj`). No hay `.sks` (no se
decodifica, por regla). Los `vmess://`, `vless://`, `trojan://` y
`ss://` dentro de los servidores son protocolos estándar ya
cubiertos por SP-DECODE.

```bash
python3 XJ_VPN_archivos.py --self-test
python3 XJ_VPN_archivos.py --file config.xj [--password CONTRASEÑA]
python3 XJ_VPN_archivos.py --link 'xj://...'
python3 XJ_VPN_archivos.py --link 'xjdev://...'
python3 XJ_VPN_archivos.py --link 'xjgcp://...'
```

## Estado de verificación

- ✅ `--self-test` de ambos scripts (7 grupos de round-trip exactos
  en archivos: `.xj` libre y bloqueado —contraseña vacía/incorrecta
  y sobre alterado rechazados—, `xj://`, `xjgcp://`, `xjdev://` v2
  XZ y v1 legacy GZIP, `xj-local-v1`, `xj-runtime-v1`).
- ✅ Núcleo AES-256-GCM verificado además contra la librería
  `cryptography` (20/20 round-trips, tag alterado detectado).
- ✅ `--url` en vivo 2026-11-14: preflight 200 + 5× 403
  `modified_app` (re-verificado con el script final).
- ⚠️ **UNVERIFIED contra un archivo real**: no hay todavía un `.xj`
  ni un enlace real exportado por la app. Lo que lo confirmaría:
  un `.xj` exportado por la app (con y sin contraseña), un `xj://`,
  un `xjgcp://` y un `xjdev://` copiados desde la app.
- ⚠️ Catálogo en vivo sin versión ni conteos (bloqueado, ver arriba).
  `ServerDto` (35 campos) y `PublicPayloadDto` documentados en
  `XJ_VPN_archivos.py` desde el DEX.

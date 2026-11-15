# SNI Tunnel - V2Ray VPN Client

- **App:** SNI Tunnel - V2Ray VPN Client
- **Package:** `com.asnly.snitunnel`
- **Versión analizada:** 1.3.0 (versionCode 32, minSdk 26, targetSdk 36)
- **Origen del APK:** APKPure (APKMirror no tenía listado para esta app).
  XAPK verificado por el manifiesto: `com.asnly.snitunnel` 1.3.0 build 32.
  Base (4.572.410 B) + split `config.arm64_v8a` (54.764.082 B, aquí viven
  todas las librerías nativas) + splits de idioma/densidad.
- **Fecha de análisis:** 2026-11-13
- **Estado en el repo SP-DECODE:** sin cobertura (se revisaron las 86
  carpetas de `decoders/Python/apps/` en la rama `feat/nuevas-integraciones`;
  lo más cercano eran falsos positivos: `CATNET_VPN` por "atnet" y
  `VIP_Snipher_Pro` por "sni").

## Hallazgo clave: NO hay catálogo propio del vendedor

SNI Tunnel es un cliente V2Ray genérico (Flutter + núcleo xray en Go,
`libgojni.so`). **No descarga ningún catálogo de un servidor del vendedor:
no hay ninguna URL propia en el DEX, en `libapp.so` (Dart AOT) ni en
`libgojni.so` (xray)**. Los únicos `https://` en `libapp.so` son del
framework Flutter y de documentación/redes sociales. La app descarga la
URL de suscripción que pone el usuario y la convierte en perfiles; el
"cloud config" es compartir configuraciones entre usuarios, no un
catálogo del proveedor.

Por eso `SNI_Tunnel.py` no descarga de una URL fija: descarga **cualquier
URL de suscripción exactamente como lo hace la app** (misma petición,
mismas cabeceras, mismos límites) y la parsea igual que ella.

## Método del catálogo (suscripción)

Petición exacta de la app (Kotlin, `SubscriptionHttpClient`):

```
GET <url de suscripción del usuario>
Accept: text/plain, application/octet-stream, */*
User-Agent: SNI-Tunnel/1.3.0 (Android)
x-hwid: <UUID aleatorio en minúsculas, persistente por dispositivo>
x-device-os: Android
x-ver-os: <versión de Android, p. ej. 14>
x-device-model: <FABRICANTE MODELO, o "Android Device">
```

- Solo HTTPS (rechaza `http` y URLs con credenciales en la URL).
- Sin redirección automática: sigue `Location` a mano, hasta 5 saltos
  (con espacios codificados a `%20`); en el 5.º salto sin resolver:
  "Too many subscription redirects."; sin `Location`:
  "Subscription redirect has no location."
- Timeouts 20 s al conectar / 60 s al leer. Límite 16 MB (16.777.216 B),
  tanto por `Content-Length` como durante la lectura.
- Cabecera `subscription-userinfo` (alias: `x-subscription-userinfo`,
  `subscription-user-info`, `x-user-info`, `user-info`,
  `profile-userinfo`): `upload / download / total / expire` (con alias
  `uploadbytes`, `downloadbytes`, `totalbytes`, `used`, `unused`, `d`,
  `expires`, `expiry`, `expiration`, `expires_at`, `expire_time`; números
  con sufijos B/KB/MB/GB/TB/KiB/MiB/GiB/TiB; expiración en epoch ms, en
  segundos si es < 10^11, o fecha `yyyy-MM-dd['T'HH:mm:ss[Z]]`).
- Errores HWID del panel: `x-hwid-max-devices-reached: true` o
  `x-hwid-limit: true` → límite de dispositivos; `404` +
  `x-hwid-not-supported: true` → el panel exige HWID. Otros no-2xx:
  "Subscription request failed with HTTP <código>."
- Si hay un transporte de túnel configurado se intenta primero y si
  falla se usa el directo; el script usa el directo (el túnel es
  configuración del usuario, no del proveedor).

Parseo del cuerpo (`SubscriptionContent.parse`):

1. Quita líneas de comentario (`# ...`) y el BOM.
2. Si ninguna línea trae `://`, intenta Base64 URL-safe de todo el
   cuerpo y vuelve a quitar comentarios.
3. Parsea líneas de enlaces `vmess://`, `vless://`, `trojan://`, `ss://`,
   `hy2://`, `hysteria2://`, `tuic://`, `socks://`.
4. Si no sale ningún perfil, intenta Clash YAML: sección `proxies:`
   (bloque `clave: valor` o diccionario en línea `{...}`), tipos `vmess`,
   `vless`, `trojan`, `ss`, `shadowsocks`, `hysteria2`.
5. Directivas del proveedor en las líneas `# clave: valor` del cuerpo
   (crudo y decodificado, primera gana; los valores pueden venir con
   prefijo `base64:`): `profile-title` (máx. 25), `support-url`,
   `profile-web-page-url`, `announce` (máx. 200),
   `profile-update-interval` (1–720 h), `hide-settings`, `providerid`
   (máx. 128), `subscriptions-sort-type` (without/ping/alphabet),
   `sub-expire`, `sub-expire-button-link`, `notification-subs-expire`,
   `fallback-url`, `new-url`, `new-domain`.
6. Dedup por `stableKey` = SHA-256 hex de tipo, servidor (minúsculas),
   puerto, uuid, usuario, contraseña, método, red, seguridad, sni,
   wsHost, wsPath, grpcServiceName, realityPublicKey, realityShortId
   unidos con NUL. `id` = UUID v3 (MD5, `UUID.nameUUIDFromBytes`) de
   `"<subscriptionId>:<stableKey>"`. Intervalo de actualización por
   defecto: 6 h.

## Prueba en vivo

**No existe una URL de catálogo del vendedor que probar** (ver arriba):
la app descarga la URL que pone el usuario. La prueba en vivo verifica
el mecanismo exacto contra un servidor local
(`work/test_fetch.py`, 17/17):

- Fetch con las cabeceras exactas de la app (User-Agent, Accept,
  `x-hwid`, `x-device-os`, `x-ver-os`, `x-device-model`) — verificadas
  byte a byte en el servidor.
- Cuerpo con directivas de proveedor + cabecera `subscription-userinfo`:
  2 perfiles (vmess + vless) y userinfo parseado
  (`upload=100, download=200, total=1073741824, expire=1893456000000`).
- Redirección 301 con espacio en `Location` seguida y resuelta
  (`/sub%20with%20space`).
- Bucle de redirecciones → "Too many subscription redirects."
- `x-hwid-max-devices-reached: true` → error de límite de dispositivos.
- `404` + `x-hwid-not-supported: true` → error de HWID requerido.
- `Content-Length` > 16 MB → error de límite.
- `require_https` sigue rechazando `http://` en el script real.

Self-test de parseo: `python3 SNI_Tunnel.py --self-test` → **34/34**
(enlaces vmess/vless/trojan/ss/hy2 en Base64 y en plano, Clash YAML,
userinfo con sufijos y fechas, directivas con límites y `base64:`,
stableKey/UUID v3, entradas vacías).

## Archivos de configuración

`SNI_Tunnel_archivos.py` — la app importa archivos de texto
(`parseDocument`, sourceKind "manual", ids UUID aleatorios, id de
suscripción ficticio "file"): lista de enlaces, blob Base64 o YAML Clash.
Self-test: **19/19**. No hay formato propio de archivo binario/cifrado
de la app; los perfiles se guardan como snapshot JSON interno de la app
(`SnapshotCodec`), que no es un formato de intercambio del proveedor.

## Enlaces de texto (intent filters, MainActivity)

Esquemas propios verificados en el manifiesto:

| Esquema | Estado |
|---|---|
| `snitunnel://connect`, `disconnect`, `toggle`, `open` | Control de la app (sin perfil) |
| `snitunnel://add/<enlace>` / `snitunnel://add/<url-https>` | Añade un perfil o una suscripción |
| `v2ray://` | Alias de enlace vmess (JSON en Base64) |
| `v2rc://` | **NO soportado**: enlace con contraseña; el descifrado vive en el Dart AOT (`package sni_ui`) y no se puede reproducir por análisis estático. Se reporta `UNSUPPORTED_SEALED`. |
| `v2rcloud://` | **NO soportado**: cloud link cifrado; el servicio en la nube aplica límites de descarga y caducidad sin ver la config. Descifrado Dart-side. Se reporta `UNSUPPORTED_CLOUD`. |
| `snitheme://` | Enlace de tema de la app, no es un perfil |
| `vmess://`, `vless://`, `trojan://`, `ss://` | Estándar, ya los cubre SP-DECODE; se parsean igual |

Los perfiles "sealed" (cifrados por dispositivo: "Configs encrypted for
this Device ID cannot be opened on any other device") tampoco se pueden
descifrar offline: la criptografía vive en el Dart AOT, sin literales
en el binario. Solo una captura en vivo (o el enlace original sin
sellar) los abriría. No se inventa ningún descifrado.

## Archivos

- `SNI_Tunnel.py` — fetch + parse de suscripciones (`decode()`, `run()`,
  CLI `--url`, `--hwid`, `--device-model`, `--os-version`, `--stdin`,
  archivo, `-o`, `--self-test`). Stdlib puro.
- `SNI_Tunnel_archivos.py` — parseo de archivos y enlaces de texto
  (CLI: archivo, `--text`, `--stdin`, `-o`, `--self-test`). Stdlib puro,
  reutiliza los parsers de `SNI_Tunnel.py`.
- `SNI_Tunnel.png` — icono lanzador 512×512, extraído de
  `res/drawable-xxxhdpi-v4/ic_launcher_adaptive.png` (432×432) del APK
  base. El XAPK no traía `icon.png`.
- `README.md` — este archivo.

Uso:

```bash
python3 SNI_Tunnel.py --url "https://panel-del-usuario.com/sub/abc123"
python3 SNI_Tunnel.py suscripcion.txt -o salida.json
python3 SNI_Tunnel_archivos.py archivo.txt
python3 SNI_Tunnel_archivos.py --text "snitunnel://add/<enlace>"
python3 SNI_Tunnel_archivos.py --text "v2rc://abc123"   # UNSUPPORTED_SEALED
```

## Detalles de la app (por si hace falta ampliar)

- Flutter (Dart AOT en `libapp.so`, 7.144.336 B) + `libflutter.so`
  (11.581.856 B) + núcleo xray en Go `libgojni.so` (35.987.384 B,
  paquete `com.asnly.snitunnel/xraymobile`: `Core.Fetch`,
  `MeasureDelay`, `ConfigProbeResult`, `HTTPResponse`, `MemoryStats`).
  Todas las librerías viven en el split `config.arm64_v8a`; el base no
  tiene `.so`.
- Tipos de proxy (`ProxyType`): VLESS, VMess, Trojan, Shadowsocks,
  Hysteria2, TUIC, SOCKS, SSH.
- Servicios: `SniVpnService`, `QuickConnectTileService`,
  `ConfigProbeService`. Receptores: `QuickConnectWidget`,
  `SubscriptionExpiryReceiver`, `BootReceiver`.
- Canales Dart: `com.asnly.snitunnel/commands` y
  `com.asnly.snitunnel/snapshot`.
- jadx 1.5.3: 955 clases, 3 errores (99 %). Evidencia en `work/`
  (`libapp-urls.txt`, `libgojni-urls.txt`, `jadx.log`, `test_fetch.py`).

## Pendiente

- Una URL de suscripción real de un panel SNI Tunnel (de un usuario de
  la app) para confirmar el fetch end-to-end contra un servidor real;
  la prueba local cubre el mecanismo completo, pero no hay catálogo
  del vendedor.
- Un enlace `v2rc://` / `v2rcloud://` real o una captura en vivo para
  los enlaces sellados/cloud (criptografía Dart-side).
- Un archivo exportado real de la app para confirmación end-to-end
  del parseo de archivos (el formato es texto plano, ya verificado
  con muestras sintéticas).
- No hay `.sks` en esta app (Pedro los excluye de todas formas).

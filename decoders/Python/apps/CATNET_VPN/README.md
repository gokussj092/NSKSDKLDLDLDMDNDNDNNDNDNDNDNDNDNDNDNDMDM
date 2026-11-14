# CATNET VPN | FAST SECURE VPN — 1.2.7 (build 29)

**NOTA DE VERSIÓN:** los resultados corresponden a la **1.2.7 (build 29,
9 nov 2026)**, la versión más reciente disponible en los espejos (APKPure).
En Google Play la versión pública actual es la **1.2.9 (13 nov 2026)**;
ningún espejo la tenía todavía cuando se hizo este análisis (APKPure solo
llegaba a 1.2.7; APKMirror sin resultados; APKCombo no resolvía por DNS).
Si la 1.2.9 cambia el método, habrá que re-analizar desde ese APK.

## Cobertura previa en SP-DECODE

El repo **ya cubre esta misma app y esta misma build**:
`decoders/Python/apps/CATNET_VPN/` (manifest: packageName net.catnet.vpn,
versionName 1.2.7, versionCode 29, método `catalog`). La carpeta NO es el
falso positivo de "atnet" que apareció en análisis anteriores: es CATNET
de verdad, con evidencia en `analysis/net.catnet.vpn/29/`. El trabajo aquí
fue **verificar ese método en este APK 1.2.7 de APKPure y probarlo en vivo**,
y entregar el script standalone para la tanda (stdlib puro, sin depender
del paquete `decoders`).

## Método del catálogo (verificado en este APK)

App Flutter (Dart AOT) + núcleo `net.xj.vpn` (ApiClient.java). Base APK sin
`.so`; las 13 librerías viven en el split `config.arm64_v8a.apk`
(libgojni.so, libxray.so, libxjicmp.so, libxjovpntune.so, libflutter.so,
libapp.so, libhysteria.so, libovpncli.so, libhev-socks5-tunnel.so,
libpingtunnel.so, libicmp-hans.so, libc++_shared.so,
libdatastore_shared_counter.so).

1. **Preflight:** GET
   `https://pussyvpn.com/xjvpn/mobile/public/app-update?app_key=pussy_vpn&current_version_code=29`
2. **Catálogo:** GET `https://pussyvpn.com/xjvpn/mobile/public/servers`

Cabeceras exactas (ApiClient.java, líneas 66-68 y 197-249): `X-XJ-App-Key` /
`X-App-Key` = `pussy_vpn` (identificador de cliente estático incluido en
la APK, no una contraseña de cuenta), `X-XJ-App-Package` / `X-App-Package` /
`X-Package-Name` / `X-XJ-Package-Name` = `net.catnet.vpn`,
`X-XJ-Version-Code` = 29, `X-XJ-Installation-Id` = UUID nuevo por
operación, `User-Agent: okhttp/4.12.0`, `Accept-Encoding: identity`. Sin
redirects, sin auth de cuenta. Host alternativo para payloads:
`https://xjdev.net/xjvpn/` (PAYLOAD_BASE_URL).

La respuesta es **JSON UTF-8 plano, sin cifrado**:
`{"success": true, "servers": [{"id": int, "servername": str, "ip": str, ...}],
"message": str, "has_defaults": bool, "def_user"/"def_pass_plain"/
"back_user"/"back_pass_plain": str, ...}`. Se conserva el documento
completo, con todos los campos y metadatos.

## Estado en vivo (2026-11-13) — fallo honesto: catálogo bloqueado por Play Integrity

- Preflight: HTTP 200, `success: true`, `maintenance: false`,
  `update_available: false`, pero **`integrity_required: true`** con un
  `integrity_challenge` (JWT: app `pussy_vpn`, pkg `net.catnet.vpn`,
  ver 29, nonce, expiración, tipo `challenge`, firmado).
- Servidores, payloads y xray_payloads (en pussyvpn.com y en xjdev.net):
  HTTP 403 `{"success": false, "modified_app": true, "message": "This app
  installation is not verified. Install the official XJ app from Google
  Play.", "play_store_url": "https://play.google.com/store/apps/details?id=net.catnet.vpn"}`.

El servidor exige un token de Play Integrity válido, que solo puede emitir
un dispositivo real con la app oficial instalada desde Google Play. La app
lo envía como cabeceras `X-XJ-Integrity-Token` / `X-XJ-Integrity-Session` /
`X-XJ-Integrity-Challenge` / `X-XJ-Request-Hash` (ApiClient.java).
**Este script NO fabrica Play Integrity ni sesiones**: si el preflight
exige verificación, se detiene con `CATNET_INTEGRITY_REQUIRED` (probado:
`CATNET_VPN.py --url` sale con exit 1 y ese mensaje). El catálogo volverá
a abrir sin cambios si el servidor deja de exigir integridad.

Esto coincide con el estado que el repo ya registraba el 2026-11-09
(`NETWORK_UNAVAILABLE`, "no se declara restaurado el catálogo"): el
servidor no ha vuelto a servir el catálogo sin verificación. En la muestra
real histórica del repo (build 27) el catálogo tenía 6 servidores.

Las rutas `payloads` y `xray_payloads` no forman parte del alcance del
catálogo público de servidores y están bloqueadas por la misma puerta.

## Archivos y textos

- **Archivos: ninguno propio.** El manifest solo tiene MAIN/LAUNCHER; no
  hay intent-filter VIEW ni asociación de extensiones. La app puede
  importar perfiles estándar (.ovpn, ya cubiertos por SP-DECODE), pero no
  define formato `.catnet` ni similar. Sin `.sks`. Por eso no hay
  `CATNET_VPN_archivos.py`.
- **Textos: ninguno propio.** No hay esquema URI (`catnet://` no existe);
  solo los protocolos estándar (vmess/vless/ss/trojan) que SP-DECODE ya
  cubre.

## Uso

```bash
python3 CATNET_VPN.py --url -o catalogo.json   # en vivo (preflight + servidores)
python3 CATNET_VPN.py catalogo.json            # decodifica un JSON guardado
python3 CATNET_VPN.py --stdin < catalogo.json
python3 CATNET_VPN.py --self-test              # 8/8
```

## Verificación

- `CATNET_VPN.py` compila; `--self-test` 8/8 (muestra sintética con el
  formato documentado + rechazo de catálogos inválidos + guarda de
  integridad).
- `--url` reproduce el fallo en vivo: preflight 200 con
  `integrity_required: true` → `CATNET_INTEGRITY_REQUIRED`, exit 1.
- Decodificación de archivo verificada con muestra sintética (el documento
  completo se conserva tal cual).
- `CATNET_VPN.png` 512×512 (icon.png del XAPK, sin cambios).

## Pendiente

- Un catálogo real (JSON de `mobile/public/servers`) para la confirmación
  de extremo a extremo, o que el servidor deje de exigir Play Integrity;
  el script lo abrirá sin cambios si eso ocurre.
- Re-analizar cuando aparezca la 1.2.9 de Play en los espejos, por si el
  método cambió.
- El descifrado del catálogo en un dispositivo real con la app oficial
  (token Play Integrity legítimo) queda fuera de este análisis offline.

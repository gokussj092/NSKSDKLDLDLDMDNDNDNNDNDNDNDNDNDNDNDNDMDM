# IP Tunnel — decodificador del catálogo y de archivos exportados

App: **IP Tunnel**, `com.iptunnel.tunnel`, **1.4.8-alpha** (versionCode 49),
minSdk 24. APK de APKPure, versión de Google Play (actualizada 11 oct 2026).
Sin cobertura previa en el repo SP-DECODE (86 carpetas en
`decoders/Python/apps/`, sin coincidencia; tampoco en `analysis/` ni en
`decoders.json`).

## Catálogo (app_config) — VERIFICADO EN VIVO

```
GET https://iptunnel.internetshub.com/api/v2/index.php?action=app_config
```

Cabeceras exactas que envía la app (clase `d71`):

| Cabecera | Valor |
|---|---|
| User-Agent | `Dalvik/2.1.0 (Linux; U; Android 14; ...)` (HttpURLConnection) |
| X-App-Id | `iptunnel-android` |
| X-App-Device | MD5(android_id) en 32 hex (`w91.f`); sin dispositivo real se fabrica uno |
| X-App-Ts | segundos unix actuales |
| X-App-Nonce | `%016x` de un aleatorio de 63 bits |
| X-App-Auth-Mode | `session_v2` |
| X-App-Version | `49` |
| X-App-Session | solo si la app ya tiene sesión (ver abajo) |

Sin un UA Dalvik, Cloudflare responde **403 "error code: 1010"**.
El modo por defecto es `session_v2`, así que **no** se envía `X-App-Sign`
(la firma HMAC-SHA256 con el secreto `ga.d()` solo se usa en el modo
`legacy_v1`). La sesión (`X-App-Session`) se obtiene en
`?action=app_attest` con un **token de Google Play Integrity** del
dispositivo — no se puede fabricar offline — pero el endpoint
`app_config` responde **200 sin sesión**, verificado en vivo dos veces
con dispositivos fabricados distintos.

Respuesta: cuerpo = **una línea Base64** = cifrado **XXTEA** (variante
`yy.l`/`yy.o`, delta `0x9A7393B4`, la misma que AR PRO) del JSON del
catálogo. Clave = primeros 16 bytes UTF-8 de `vc.z`:

```
8f3c7a1e6d2b4c9f0a5e1d7c3b8f6a2e9c4d1f7b0a3e6c2d5f8a1b9c7e4d2a6
```

El JSON tiene: `Version`, `Message`, `Servers[]`, `Tweaks[]`,
`AdsSettings`, `TimerSettings`. Cada servidor trae SSH/SSL/Proxy,
credenciales, y los enlaces `Vmess` / `Vless` / `Trojan` / `Hysteria` +
`UDPCertificate` (config OpenVPN completa del cliente).

### Resultado en vivo (2026-11-13, `IP_Tunnel.py --url`)

- **Version 1.91**, Message "OTA Update to keep IP Tunnel Optimised."
- **3 servidores**: INDIA (`in.iptunnel.eu.org`), UNITED STATES
  (`us.iptunnel.eu.org`), USE WITH ORANGE TWEAK (`us.iptunnel.eu.org`).
  Los 3 con Vmess, Vless y Trojan. Sin marca free/premium
  (`AccessTier` vacío en los 3).
- **366 tweaks, 151 con Payload no vacío.** Tipos:
  1:7, 2:138, 3:76, 4:4, 5:3, 6:19, 7:110, 8:1, 9:1, 10:3, 11:3, 12:1.

El catálogo incluido en el APK (`vc.y`, `bundled_config.b64`) es solo un
marcador: **Version 1.00, 1 servidor ("UPDATE APP"), 1 tweak**.

### Otros endpoints (misma base, `vc.d`–`vc.v`)

`app_coin_updates`, `app_coin_state`, `app_coin_sync`,
`app_rewarded_ad_complete`, `app_entitlements`, `app_activate_pro`,
`app_leaderboard_current`, `app_premium_server`, `app_redeem_code`,
`app_sign_import`, `app_cloud_publish`, `cloud_fetch`, `cloud_touch`,
`app_policy_public`, `support_submit`, `support_my_tickets`,
`support_reply`, `app_attest` (sesión). Los premium requieren sesión
Play Integrity y quedan fuera de este decodificador.

## Archivos exportados (IP_Tunnel_archivos.py)

La app **no** registra extensión propia ni esquema URI en el manifest:
exporta con `ACTION_CREATE_DOCUMENT` (el usuario elige el nombre) e
importa con `ACTION_GET_CONTENT` (selector de archivos). El contenido
es una línea Base64:

```
Base64( XXTEA( JSON_exportación , clave="@Adedayo's WeTunnel" ) )
```

El JSON tiene: `PSInstall`, `DeviceID`, `RootBlock`, `isBlockVPN`,
`isXposed`, `isBlockAppList`, `ConfigAppBlockList`, `MobileData`,
`ExpireDate`, `Message`, `Config`, `Server` (o `"none"`).

**Firma:** la app exige firma RSA válida al importar (`vc.F = true`).
Campos `Sig` (Base64url), `SigTs`, `SigKid` (= `"k1"`), `SigV`,
`SigAlg` (`"RS256"`). Se verifica con SHA256withRSA y la clave pública
incrustada `vc.H`, sobre el payload canónico de 15 líneas separadas por
`\n` (ExpireDate, RootBlock 1/0, MobileData 1/0, Message, Config,
Server, DeviceID, PSInstall 1/0, isBlockVPN 1/0, isBlockAppList 1/0,
ConfigAppBlockList, isXposed 1/0, SigTs, SigKid, SigV).
`IP_Tunnel_archivos.py` **verifica** la firma; no puede crear una
válida (haría falta la clave privada del vendedor): un archivo
re-cifrado con `--encrypt` se lee aquí, pero la app lo rechazará al
importar sin firma válida.

El script también abre blobs del catálogo (misma envoltura XXTEA con la
clave `vc.z`), como el valor `DATA` de `system.db` (tabla
`iptunnel_table`): prueba ambas claves e informa cuál abrió el archivo.

## Archivos de texto (URI schemes)

**Ninguno propio.** Solo esquemas estándar (`vmess://`, `vless://`,
`trojan://`, `ss://`, `hysteria2://`) dentro de los datos del catálogo,
ya cubiertos por SP-DECODE, y los enlaces `https://t.me/iptunnel_bot`
y `https://t.me/IPTunnelVPN` de la app. La importación de archivos es
por selector, sin filtro de extensión. No hay `.sks`.

## Uso

```bash
python3 IP_Tunnel.py --url --summary            # catálogo en vivo
python3 IP_Tunnel.py --url -o catalogo.json      # + guarda el JSON
python3 IP_Tunnel.py --file catalogo.b64         # blob guardado
python3 IP_Tunnel.py --asset --summary           # catálogo del APK (v1.00)
python3 IP_Tunnel.py --self-test                 # 10/10 checks

python3 IP_Tunnel_archivos.py exportado.b64 --summary
python3 IP_Tunnel_archivos.py --encrypt export.json -o exportado.b64
python3 IP_Tunnel_archivos.py --self-test        # 11/11 checks
```

## Archivos

| Archivo | Descripción |
|---|---|
| `IP_Tunnel.py` | Decodificador del catálogo (`decode()` + `run()` + CLI `--url`, stdlib puro) |
| `IP_Tunnel_archivos.py` | Decodificador de archivos exportados + blobs de catálogo, con verificación RS256 |
| `IP_Tunnel.png` | Icono 512×512 (del XAPK) |
| `catalog_sample.b64` | Respuesta viva real de app_config (Version 1.91, 158.656 B) |
| `bundled_config.b64` | Catálogo incluido en el APK (`vc.y`, Version 1.00) |
| `README.md` | Este archivo |

## Notas de implementación

- Las cadenas de la app están ofuscadas con R8 (`od2`/`nd2`: `Random`
  con semilla + XOR por `long`, con la sutileza de que `nextLong()` de
  Java usa enteros con signo y el segundo `next(32)` negativo pide
  prestado 1 a la mitad alta). El descifrador está en
  `work/od2.py` y las cadenas descifradas en `work/jadx-out/sources/`
  (`*_dec.java`).
- Re-cifrado verificado byte a byte: re-cifrar el JSON del catálogo
  incluido reproduce `vc.y` exacto, y re-cifrar el catálogo vivo
  reproduce el blob vivo exacto.
- `assets/config/config.json` (2.520 caracteres, 16 símbolos: dígitos
  superíndice ⁰–⁹ + `· ′ ‽ ' : ,`) quedó **sin resolver**: ningún
  camino de código lo abre (el escáner OpenVPN solo lista la raíz de
  assets buscando `.ovpn`; `readTextFromAssets` solo se llama para
  `v2ray_config.json`). Se probaron las hipótesis Jacodes/Base64 con
  resolución por frecuencia y simulated annealing (dos mapeos llegan a
  1260/1260 bytes Base64-válidos, pero el Base64-decodificado es
  basura y no abre con XXTEA/vc.z). Probable asset muerto o leído por
  código nativo no trazado. No afecta al catálogo: el incluido es
  `vc.y` y el vivo es `app_config`.

## Pendiente

- Un archivo exportado real desde un teléfono para confirmación
  end-to-end (el formato está verificado por round-trip, pero no con
  un archivo real de la app; en particular, la firma RS256 de un
  archivo real para validar `signature_status` contra `vc.H`).
- Un `X-App-Session` real (de un dispositivo con la app oficial) para
  probar los endpoints premium (`app_premium_server`,
  `app_entitlements`); el catálogo gratuito no lo necesita.
- `assets/config/config.json`: identificar su lector real o confirmar
  que es un asset muerto.
- Re-analizar si cambia la versión (la clave `vc.z`, el delta XXTEA o
  la URL base están en el APK).

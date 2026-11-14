# Shield Tunnel / One Shield Tunnel — decodificador de catálogo y archivos

**App:** One Shield Tunnel (`one.shield.tunnel`) **v1.11.06.1** (versionCode 79,
minSdk 24), en Google Play y APKPure como "One Shield Tunnel" (desarrollador
sando--k). Fork de v2rayNG (com.v2ray.ang) con núcleo Sandok/Ultra
(AndroidLibXrayLite, Go 1.20) y cadenas ofuscadas con LSParanoid
(Deobfuscator$OneShieldTunnel$app, 21 chunks, 8,229 call sites).

**Estado: CATÁLOGO EN VIVO COMPLETO.** El endpoint responde HTTP 200 y el
cuerpo abre con K1: **versión 7.15, 32 servidores, 440 redes, 433 con
Payload** (verificado 2026-11-14). A diferencia de Marvs SSH / T20-VPN, RNV
y AT NET (misma familia StrongTeam), la clave en vivo de Shield Tunnel **no**
ha rotado.

**Distinto de:** Shield VPN (`litron.shield.vpn`, tanda 7) y Guruz Tunnel
(tanda 8). Paquete, endpoint y claves distintos; nada se reutilizó de ellos
sin verificarlo en ESTE APK (Shield usa Argon2 con memoria 16384 KiB;
Marvs/RNV usan 8192 KiB).

## Archivos

| Archivo | Descripción |
|---|---|
| `Shield_Tunnel.py` | Decodificador del catálogo (`decode()` + `run()` + CLI `--url`). Python stdlib puro. |
| `Shield_Tunnel_archivos.py` | Decodificador de archivos de perfil (ver sección Archivos). |
| `Shield_Tunnel.png` | Icono 512×512 (icon.png del XAPK). |
| `configfile.json` | Asset incluido en el APK (catálogo v1.01, 34 servidores, 555 redes). |
| `catalog_sample.b64` | Cuerpo en vivo descargado 2026-11-14 (668,772 B, SHA-256 `262d8a20…`). |

## Catálogo en vivo

La app actualiza con `CU()` (Go, libgojni.so) y descarga el catálogo con un
POST exacto (no un GET):

```
POST https://strongteam.co/api/oneshieldtunnel/
Content-Type: application/x-www-form-urlencoded
User-Agent: Go-http-client/1.1
Body: hash=xsandokUpdatex
```

Sin autenticación, sin cookies, sin cabeceras extra. El servidor responde
HTTP 200, `text/plain; charset=utf-8`, cuerpo chunked: una sola línea Base64
(668,772 B el 2026-11-14, SHA-256
`262d8a20f5524c13ea2bb76e4c8fd2e5c6f8438d6569536c688d1c8b99e6ddaa`).

## Sobre cifrado

```
Base64( salt[16] || nonce[12] || AES-256-GCM(key, nonce, AAD=salt) )
key = Argon2id(password, salt, time=3, memory=16384 KiB, threads=1, 32 B)
```

Dos contraseñas de formato, construidas por el núcleo Go (desensamblado de
`decrypt()` y `DO()` en libgojni.so: cada una carga 16 bytes de `.rodata` y
sobrescribe la cola con inmediatos `movk`):

- **K1 `NewDecryptLibPasswordII`** (23 B) — `decrypt()`/`Encrypt()`, el
  camino del catálogo en vivo (CU descifra la respuesta HTTP con ella).
  `.rodata` 0x3564a9 + `"sswordII"`.
- **K2 `NewDecryptLibPassword`** (21 B) — `DO()`/`do_()`, el asset incluido
  y las cadenas de archivo. `.rodata` 0x3534bb + `"Password"`.

El script prueba K1 primero y luego K2, e informa cuál abrió el sobre.
Son constantes de formato de la app, no credenciales de cuenta.

El JSON descifrado es el esquema Sandok/Ultra: `Version` (str),
`ReleaseNotes`, `Telegram`, `WhatsApp`, `Facebook`, `DefOVPNUser`,
`DefOVPNPass`, `HysteriaUser`, `HysteriaOBFS`, `DefaultOVPNCert`,
`isTimerOn`, `timetoadd`, `Servers[]` y `Networks[]`. **Sin distinción
gratis/premium** (no hay campo Category): los 32 servidores van juntos.

### Campos cifrados dentro del catálogo

La mayoría de los valores de texto dentro de `Servers[]`/`Networks[]` son
el mismo sobre (Base64(salt||nonce||GCM), Argon2id m=16384) y abren con
**K2**. Verificado en el catálogo en vivo 2026-11-14: **todos** los campos
Base64 que parsean como sobre (44+ B) abrieron con K2, 0 fallos
(Servers: 32/32 `ServerIPHost`, 32/32 `SlowDNSKey`, 32/32 `UDP_obfs`;
Networks: 418/418 `V2rayAddress`, 418/418 `V2raySNI`, 418/418 `Payload`,
42+376 `V2rayConfig`). Los textos vacíos son normales en campos que el
servidor deja en blanco (p. ej. `OVPNUser` cuando `isdefUser=true`, que usa
`DefOVPNUser`). Los campos en claro (`Name`, `Flag`, puertos, `TunnelType`,
`BugDNS`...) se dejan tal cual.

`decode()` devuelve el catálogo con los campos tal como vienen del servidor
(misma convención que los scripts de RNV/Marvs), porque cada campo necesita
su propia derivación Argon2id (~30 s en Python puro, ~0,3 s con
argon2-cffi) y descifrar cientos de campos en bloque no es práctico aquí.
`decrypt_field(valor)` abre un solo campo con K2 para quien necesite el
valor en claro (host del servidor, usuario, contraseña, payload, SNI...).

Ejemplos descifrados del catálogo en vivo (K2):

- `ServerIPHost` → `ovpn-1084010758275.asia-southeast1.run.app`
- `UDP_obfs` → `sandok`
- `SlowDNSKey` → `5d30d19aa2524d7bd89afdffd9c2141575b21a728ea61c8cd7c8bf3839f9`
- `Payload` → `CONNECT www.setabganj.info:4443 HTTP/1.1[crlf]Host: www.setabganj.info[crlf]Prox...`
- `V2rayConfig` → JSON v2ray completo

## Archivos de perfil

**Formato `.ost`** (declarado en el manifest: `application/x-ost`,
`application/octet-stream`, `pathPattern .*\.ost`, activity
`com.v2ray.ang.ui.ConfigFileParser`).

- **Importar** (`ConfigFileParser.onCreate`, cadenas LSParanoid resueltas):
  lee el archivo como texto y prueba en orden `Libv2ray.parseConfig()`
  (config plana), `Libv2ray.gv()`/`gc()` y `Hometab.Companion.a()` =
  `Libv2ray.do_()` (el Go `DO()`, clave K2); si nada abre,
  "Invalid JSON or decryption error".
- **Exportar/compartir** (`NetworkAdapter`): `Gson.toJson(NetworkList)` →
  `Libv2ray.encrypt()` (el Go `Encrypt()`, clave K1) → archivo
  `<nombre>.ost` (el sufijo ".ost" es una cadena LSParanoid resuelta).

`Shield_Tunnel_archivos.py` prueba ambas claves (K1 primero, luego K2) y
reporta cuál abrió el sobre. El texto descifrado es el perfil en JSON
(NetworkList: `Name`, `TunnelType`, `Payload`, `SNI`, `V2rayConfig`...).
También acepta el asset `configfile.json` (mismo sobre, K2).

Uso:

```bash
python3 Shield_Tunnel_archivos.py perfil.ost
python3 Shield_Tunnel_archivos.py --self-test
# {"self_test": "OK", "key": "K2", "version": "1.01", "servers": 34, "networks": 555}
# {"round_trip": "OK", "key": "K1"}
# {"round_trip": "OK", "key": "K2"}
# (la autoprueba completa tarda ~8 min: asset + 2 round-trips, cada
#  descifrado Argon2id m=16384 en Python puro tarda ~30-40 s)
```

Pendiente: un `.ost` real exportado por la app en un teléfono para la
confirmación de extremo a extremo.

## Esquemas URI

Definidos en el manifest (`com.v2ray.ang.ui.UrlSchemeActivity`):

- `v2rayng://install-config?url=<...>` — instalar una configuración
  (esquema estándar de v2rayNG, no propio de Shield).
- `v2rayng://install-sub?url=<...>` — instalar una suscripción.
- Además acepta `ACTION_SEND` con `text/plain` (`EXTRA_TEXT`).

No hay un esquema propio tipo `shieldtunnel://`; los enlaces de texto son
los estándar `v2rayng://` y los enlaces vmess/vless/trojan/ss habituales
de v2rayNG.

## Uso

```bash
# Descargar y descifrar el catálogo en vivo
python3 Shield_Tunnel.py --url

# Descifrar un cuerpo guardado (o el asset configfile.json)
python3 Shield_Tunnel.py configfile.json
python3 Shield_Tunnel.py catalog_sample.b64

# Autoprueba con el asset incluido
python3 Shield_Tunnel.py --self-test
# {"self_test": "OK", "key": "K2", "version": "1.01", "servers": 34, "networks": 555}
```

Un descifrado del sobre tarda ~30-40 s (Argon2id m=16384 en Python puro);
la autoprueba completa tarda ~4 min (prueba K1, que falla, y luego K2).

## Verificación

- Asset `configfile.json`: abre con K2 (tag GCM auténtico, JSON válido,
  Version "1.01", 34 servidores, 555 redes). SHA-256 del asset:
  `ae4a7b72044b354826449700c031fc3da93dd94ae0834a083b3c828d5bb32880`.
- Cuerpo en vivo 2026-11-14: HTTP 200, 668,772 B, abre con K1
  (Version "7.15", 32 servidores, 440 redes, 433 con Payload).
- Criptografía en Python puro verificada byte a byte contra argon2-cffi
  y PyCryptodome (Argon2id m=16384 y AES-256-GCM).
- Repo SP-DECODE: sin cobertura previa de `one.shield.tunnel`
  (revisado 2026-11-14 en `feat/nuevas-integraciones`, 86 carpetas).

## Pendiente

- Archivo de perfil real exportado por la app en un teléfono para
  confirmar el decodificador de archivos de extremo a extremo.

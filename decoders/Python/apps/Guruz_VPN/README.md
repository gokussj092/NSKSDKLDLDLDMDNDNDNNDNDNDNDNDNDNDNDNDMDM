# Guruz VPN — guruz.vpn.tunnel

Descifrador del catálogo de **Guruz VPN 18.4** (versionCode 184, minSdk 32),
XAPK de APKPure (misma versión que Google Play, actualizada 7 nov 2026),
57.481.836 B,
SHA-256 `ae3a0296b5eaaf0315cfb7801ff80f0673cf79f8dde874284f160fc31f93bb67`.

> **No es la misma app que Guruz Tunnel** (`com.guruz.tunnel`, 18.6, tanda 8).
> Mismo framework (tekidoer) y misma familia de cifrado STGCM, pero paquete
> distinto, sufijos distintos (`.GV.` / `GVCR1.` en vez de `.GT.` / `GTCR1.`),
> claves distintas y URL distinta. Nada de Guruz Tunnel se reutilizó sin
> verificarlo en ESTE APK. El repo SP-DECODE no cubre esta app
> (sin carpeta en `decoders/Python/apps/`, sin `analysis/` y sin mención
> en `decoders.json`, rama `feat/nuevas-integraciones`, 2026-11-13).

## Método (verificado en este APK y en vivo)

```
GET https://raw.githubusercontent.com/guruzgh-ed/edd/refs/heads/main/gv.js
```

- Petición exacta de la app (`bw0.doInBackground`, `HttpURLConnection`):
  método `GET`, connect timeout 15 s, read timeout 20 s, **sin seguir
  redirecciones automáticamente** (solo se sigue un `Location` HTTPS),
  sin autenticación ni parámetros. `If-None-Match` / `If-Modified-Since`
  solo se envían cuando la app ya tiene un etag / fecha guardados
  (primera descarga: GET plano, User-Agent Dalvik por defecto, ninguna
  otra cabecera). La app rechaza cuerpos de más de 8 MiB.
- El cuerpo es una línea: `STGCM3.GV.<b64url(IV 12 B)>.<b64url(ct + tag 16 B)>`
- **AES-256-GCM**, AAD = `STGCM3.GV.` (el prefijo de 10 bytes, con el punto)
- El JSON resultante trae `version`, `schema_version`, `config_revision`,
  `reset`, `message`, `url_updater`, `minimum_app_version`, `force_update`,
  ids de AdMob, `Servers[]` y `Tweaks[]`.
- Cada valor de cadena dentro del JSON está a su vez codificado:
  - **r95** (mismas constantes que Guruz Tunnel): por índice `i`,
    `i%4==0` → XOR `0x57712`; `i%4==1` → XOR `0x5a0c38d7`;
    `i%4==2` → XOR `0xA25A5826`; `i%4==3` → NOT (todo a 16 bits,
    auto-inverso). Se detecta por el alfabeto ofuscado
    (U+3800–U+38FF, U+5800–U+58FF, U+7000–U+7FFF, U+FF80–U+FFDF).
  - `u8:` + Base64 (campo `message`).
  - `GVCR1.<b64url(IV 12 B)>.<b64url(ct + tag 16 B)>` → AES-256-GCM,
    AAD = `GVCR1.` (credenciales, enlaces vmess/vless/wireguard/
    hysteria2, perfiles OpenVPN, detalles UDP y Payloads de tweaks).

## Claves (constantes públicas del formato, de `libfrkudp.so`)

Cada clave sale de un blob de 32 bytes en `.rodata` como
`key[i] = blob[i] XOR 0xa7 XOR ((base + 73*i) & 0xff)`:

| Clave | Blob `.rodata` | Base | Valor |
|---|---|---|---|
| `KEY_CONFIG3` (STGCM3) | `0x4d80c` | `0x51` | `b1445529ff46895824aeae1874b403278b63c690fb8046c2df5aa3393e5346c4` |
| `KEY_CRED` (GVCR1) | `0x4d82c` | `0x71` | `4914f051e45c820f906d6cdf6ef2d29c0106d5b7f973ce6d11624316bdb3f861` |
| `KEY_CONFIG2` (STGCM2, legado) | `0x4d84c` | `0x5d` | `77cb41f2a7aeb59ef152d7e374c8014e37b5c6ce04a84e2437c3bd722e176476` |

Recuperadas desensamblando las tres funciones de derivación en
`libfrkudp.so` (0xdbcf0 base 0x5d, 0xdcffc base 0x51, 0xdd318 base 0x71;
misma forma de derivación que Guruz Tunnel, blobs/bases distintos) y
verificadas descifrando el seed del APK y el catálogo en vivo
(los tags GCM verifican). No son credenciales de ninguna cuenta.

## Resultado en vivo (2026-11-13, `--url`)

- HTTP 200, 601.866 B,
  SHA-256 `51cadd312ab151b07029f10ab9b44f63e530ed8f804076b1f3add54bc8195ad4`
- **Versión 0.7, config_revision 6, minimum_app_version 184,
  force_update true**
- **49 servidores: 38 PREMIUM, 10 VIP, 1 PRIVATE, 0 gratis**
- **887 tweaks, 436 con Payload** (430 GVCR1. + 6 vacíos de OpenVPN)
- **517 valores GVCR1., todos descifran (0 fallos)**
- ETag `44e4bd8f3de507a1033d4548a36356e9fc87d55e968c1a9e934680ee365579a0`
  (un segundo `--url --etag <valor>` responde HTTP 304, como la app)

El espejo antiguo `guruzgh-ed/conf/gv.js` sirve el mismo catálogo en
config_revision 4 (cuerpo distinto); la `url_updater` del propio
catálogo apunta a `edd`, así que `edd` es la URL canónica del script.
El seed incluido en el APK todavía apunta a `conf` (es anterior al
cambio de repo); la app sustituye esa URL por la del catálogo descargado.

Modos de servidor: xray 8, ovpn 4, wg 4, hy1 6, hy2 4, cf 1, ssh 7,
ws 6, bhttp 3, slowdns 4, gcp 1, xray_gcp 1. Los valores descifrados
incluyen enlaces `vmess://`, `trojan://`, `wireguard://` e
`hysteria2://`, perfiles OpenVPN completos y credenciales SSH
(`eddi` / `eddi` en los servidores de ejemplo; `Fenix7` en BHTTP).

## Uso

```bash
python3 Guruz_VPN.py --url [--summary] [-o salida.json]
python3 Guruz_VPN.py --url --etag "<etag>" --modified "<fecha>"  # como la app
python3 Guruz_VPN.py --file gv.js [-o salida.json]
python3 Guruz_VPN.py --self-test
```

Solo biblioteca estándar (Python 3.10+); el AES-256-GCM es Python puro
(mismo núcleo verificado en Guruz Tunnel / E-SAN / RNV). La descarga
tarda ~17 s por el AES en Python puro. `--self-test` usa el seed real
del APK (versión 0.1, revisión 1, 1 servidor, 1 tweak) más round-trips
de los tres sobres y r95.

## Archivos

- `Guruz_VPN.py` — `decode()` + `run()` + CLI `--url/--file/--self-test`
- `Guruz_VPN.png` — icono 512×512 RGBA (icono adaptativo del APK:
  foreground 432×432 sobre fondo blanco #FDFDFD, reescalado a 512×512;
  el XAPK no trae `icon.png`)
- `README.md` — este archivo

## Lo que NO hay (verificado, no es un descuido)

- **Sin formato propio de archivo**: el manifiesto no declara ningún
  `ACTION_VIEW`, ninguna extensión propia, ningún file picker ni
  esquema URI propio (`guruzvpn://` no existe). Por eso **no hay
  `Guruz_VPN_archivos.py`**. La configuración guardada vive cifrada
  (sobre `STGCM3.GV.`) en la base SQLite de la app
  (`system.db`, tabla `spkmoder_table`, columnas `ID, DATA`), no en
  un archivo del usuario; cuando la app no puede leerla pide
  "re-importar", es decir, volver a descargar del updater.
- **Sin esquema URI propio**: las únicas rutas de importación son las
  de la librería genérica V2Ray ANG (enlaces estándar
  `vmess://`, `vless://`, `trojan://`, `ss://` y JSON de V2Ray), que
  SP-DECODE ya cubre. Los enlaces estándar que aparecen como valores
  descifrados en el catálogo no necesitan un decodificador propio.
- **Sin `.sks`**: la app no usa ese formato (excluido por regla).

## Qué falta (pendiente)

- Nada para cerrar el método: el catálogo se verificó en vivo de
  principio a fin (descarga → descifrado → 517/517 valores GVCR1.).
- Si el proveedor rota las claves o cambia la URL del updater, el
  script dejará de abrir el catálogo y habrá que re-analizar
  `libfrkudp.so` (los blobs están en `.rodata`, la derivación es la
  misma forma). Si el catálogo pasa a `STGCM2.GV.`, el script ya lo
  abre con `KEY_CONFIG2`.
- Un `profile.json` / `system.db` real de un teléfono serviría para
  confirmar el formato guardado, pero no es necesario: el seed del
  APK ya es un vector real de ese formato.

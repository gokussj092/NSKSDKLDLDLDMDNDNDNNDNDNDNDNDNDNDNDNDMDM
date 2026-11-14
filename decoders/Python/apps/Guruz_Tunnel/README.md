# Guruz Tunnel 18.6 (com.guruz.tunnel) — decodificador de catálogo

App de la familia tekidoer (com.tekidoer.speedtunnel, SplashActivity;
servicios com.tekidoer.sshbase + V2Ray com.v2ray.ang). Sin cobertura en
el repo de SP-DECODE (verificado 2026-11-13, rama
feat/nuevas-integraciones, 86 carpetas; solo AustroPlus_VPN es de la
misma familia). Método nuevo, verificado en ESTE APK.

## App

- Guruz Tunnel, com.guruz.tunnel, 18.6 / build 186, minSdk 32.
- XAPK de APKPure (APKMirror sin listado), 57.597.795 B, SHA-256
  2cb30ffdbd5cd806b2a4da679e559fc973b13cc00e37e38e0aeaac1143d07c92.
  Extraído a `apk/` (base + config.arm64_v8a + config.en/fr/xxhdpi +
  manifest.json). El XAPK NO trae icon.png: el PNG se sacó del icono
  del APK (`res/mipmap-xxxhdpi-v4/ic_launcher.webp`, 192×192) y se
  redimensionó a 512×512.
- Librerías nativas: la base NO tiene .so; las 14 están en
  config.arm64_v8a.apk: libgojni.so (30,5 MB), libovpn3.so, libdns.so,
  libhysteria / libhysteria2, libtun2socks, libfrkudp.so (982.160 B,
  donde vive el descifrado del catálogo), libpdnsd, libmmkv,
  libconscrypt_jni, etc.
- El primer analista fue interrumpido a mitad del trabajo; este análisis
  retoma su trabajo parcial (`work/`: jadx-out, smali, dex-strings.txt,
  `harvest.py`, `zl2.py`, `seed_config.txt`) sin rehacer la extracción.

## Método del catálogo

```
GET https://raw.githubusercontent.com/guruzgh-ed/conf/refs/heads/main/gt.js
  HTTPS GET, HttpURLConnection; la app envía If-None-Match /
  If-Modified-Since solo si ya tiene un etag guardado, así que la
  primera descarga es un GET plano (sin auth ni parámetros).
  -> una línea: STGCM3.GT.<b64url(IV 12 B)>.<b64url(ct + tag 16 B)>
  -> AES-256-GCM, clave KEY_CONFIG3, AAD = b"STGCM3.GT."
  -> JSON {version, url_updater, minimum_app_version, force_update,
     Servers[], Tweaks[]}
```

Cada valor de cadena dentro del JSON lleva a su vez una codificación:

- **r95** (MainActivity.j0 → r95.lI11Il1): por índice de carácter i,
  i%4==0 → XOR 0x57712; i%4==1 → XOR 0x5a0c38d7; i%4==2 → XOR
  0xA25A5826; i%4==3 → NOT (todo a 16 bits; auto-inverso). Se detecta
  por el alfabeto ofuscado (U+3800–U+38FF, U+5800–U+58FF, U+7000–U+7FFF,
  U+FF80–U+FFDF) y solo se acepta si el descifrado no deja ningún
  carácter de ese alfabeto. El texto plano con emoji (p. ej. los nombres
  de tweaks "🌏 Worldwide | ...") NO está ofuscado y se deja tal cual.
  Los pares sustitutos UTF-16 del descifrado se combinan en el emoji real.
- **u8:** + Base64 (campos de mensaje).
- **GTCR1.\<b64url(IV 12 B)>.\<b64url(ct + tag 16 B)>** → AES-256-GCM,
  clave KEY_CRED, AAD = b"GTCR1." (credenciales, enlaces vless /
  hysteria2 / wireguard, perfiles OpenVPN, detalles UDP, Payloads).

Claves (constantes públicas de formato de la app, recuperadas de
libfrkudp.so por emulación Unicorn de nDecryptConfig /
nDecryptCredential; NO son credenciales de cuenta). Cada clave deriva
de un blob de 32 B en .rodata como
`clave[i] = blob[i] XOR 0xa7 XOR ((base + 73*i) & 0xff)`:

| Sobre | blob (.rodata) | base | clave |
|---|---|---|---|
| STGCM3 (config) | 0x4d968: 2866cd53…01018c | 0x51 | de5b89d8…307903 |
| GTCR1 (credencial) | 0x4d988: 6134dcd7…871f04 | 0x71 | b729783c…647eb |
| STGCM2 (config legacy) | 0x4d9a8: 43c3d29d…16062 | 0x5d | b9c29a02…42cf1 |

El descifrado nativo se verificó además con el certificado de firma
del APK (V3.1 SHA-256 71e5d684…; el código nativo comprueba el hash
SHA-256 del certificado firmante, pero la emulación descifró igual con
el certificado V3.0, así que esa comprobación no bloquea el descifrado).
La config se guarda en la app en `system.db` (tabla spkmoder_table,
columna DATA) como blob STGCM; el seed de primer arranque
(gf1.I1l1Il1) es un sobre STGCM3 y es el vector de --self-test.

## Prueba en vivo (2026-11-13, con el propio script --url)

- HTTP 200, 904.525 B, SHA-256
  d1de1c189456f1d1c996f008de8c083e70441966f34bb256023890818b630188.
- Catálogo **versión 1.1**, minimum_app_version 186, force_update true,
  schema_version 2, config_revision 11.
- **76 servidores (65 PREMIUM, 11 VIP, 0 gratis)**, 1.198 tweaks,
  618 con Payload. 795 valores GTCR1., todos descifran (0 fallos);
  4.157 valores r95 descifrados, 1 u8:.
- Países top de servidores: us 22, de 16, fr 13, za 9, jp 5.
- Modos de servidor: ssh 10, ws 11, xray 9, hy1 9, hy2 7, wg 7,
  ovpn 7, xray_gcp 6, slowdns 5, bhttp 3, cf 1, gcp 1.
- Modos de tweak: ssh 590, ws 356, xray 70, slowdns 65, cf 55,
  hy1 30, gcp 11, xray_gcp 10, ovpn 7, hy2 2, bhttp 1, wg 1.
- Servidores con SSHHost: 12; con V2ray443: 11; con Hysteria2Details: 6;
  con WireGuardDetails: 10; con OpenVPNProfile: 10.
- Ejemplo (servidor 0): "SSH Global [01]", us, PREMIUM, SSHHost
  159.195.17.66, V2ray443 = vless://…@ca.vpnguruz.site:443,
  Hysteria2Details = JSON guruz-hy2-v1 (hysteria2://…@us.vpnguruz.store:443),
  WireGuardDetails = enlace wireguard://, OpenVPNProfile = .ovpn completo.
- El seed incluido (primer arranque): versión 0.1, 1 servidor, 1 tweak.

## Uso

```
python3 Guruz_Tunnel.py --url [-o catalogo.json]
python3 Guruz_Tunnel.py --file gt.js [-o catalogo.json]
python3 Guruz_Tunnel.py --self-test
```

`--self-test` descifra el seed real del APK (versión 0.1, 1 servidor,
1 tweak, UDPDetails "edd.com#edd#edd") y hace round-trip de los sobres
STGCM3 / STGCM2 / GTCR1. y de r95. Solo biblioteca estándar (AES-256-GCM
en Python puro, mismo núcleo que E-SAN / RNV); el descifrado del
catálogo vivo (~678 KB de JSON) tarda ~12 s.

## Archivos

La app NO tiene formato propio importable (sin ACTION_VIEW para
archivos ni extensión propia en el manifiesto; sin picker de archivos
en MainActivity; la única cadena "Config import" es de la librería
genérica V2Ray ANG y maneja enlaces vmess/vless/trojan/ss y JSON de
V2Ray, ya cubiertos por SP-DECODE) → NO hay Guruz_Tunnel_archivos.py.
Sin .sks.

## Esquemas de texto

Ninguno propio: el manifiesto no declara esquema personalizado ni App
Links (solo MAIN/LAUNCHER en SplashActivity; los VIEW/https son
`<queries>` de visibilidad de paquetes, no intent filters). Los
servidores del catálogo sí contienen enlaces estándar vless://,
hysteria2:// y wireguard:// como valores descifrados; esos protocolos
ya los cubre SP-DECODE.

## Entregables

- `Guruz_Tunnel.py` — SHA-256
  ec3640c59938825464a92f8dc81f8f066f7d2ac22dc46dd1c0fd7356adbd3eb8;
  stdlib puro, decode() + run() + CLI --url/--file/--self-test/-o;
  --self-test OK; --url vivo v1.1 76/1198/618; --file sobre el blob
  vivo idéntico al --url.
- `Guruz_Tunnel.png` — 512×512 RGBA, del ic_launcher.webp del APK.
- `README.md` (este archivo).
- Evidencia en `work/` (jadx-out, smali, dex-strings.txt, harvest.py,
  zl2.py, guruz_native.py — emulación Unicorn de libfrkudp.so —,
  seed_config.txt, seed_decrypted.json, live_gt.js, live_decrypted.json,
  live_decoded.json, headers.txt, manifest.txt, signer_cert_v2.der).

## Pendiente

Nada para cerrar el método (catálogo verificado en vivo de extremo a
extremo; el seed verifica el camino offline). Si el servidor rota las
claves o cambia la URL (guruzgh-ed/conf/gt.js), hay que re-analizar
libfrkudp.so en el APK nuevo. No hay servidores gratis en este
catálogo: los 76 son PREMIUM/VIP.

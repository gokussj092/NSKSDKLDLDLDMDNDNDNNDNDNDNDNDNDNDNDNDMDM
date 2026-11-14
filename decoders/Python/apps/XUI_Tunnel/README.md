# XUI Tunnel VPN 6.0 (com.xui_tunnel) — SP-DECODE

## La app

- **App:** XUI Tunnel VPN, `com.xui_tunnel`, versión 6.0, build 6, minSdk 24.
- **Origen:** XAPK de APKPure,
  `~/workspace/browser_downloads/sess-930646275/browser-download-20261114T041118.357393487Z-4-XUI_Tunnel_VPN_6.0_APKPure.xapk`
  (55,484,038 B, SHA-256
  `63489026672c05c9f36ef2cdeba66e8a7df4d51a6c324e9c74d6a81b32ea2192`).
- **Extraído en** `apk/` (base `com.xui_tunnel.apk` + `config.arm64_v8a.apk` +
  `config.en`/`config.mdpi` + `icon.png` + `manifest.json`; manifest
  verificado: `com.xui_tunnel` 6.0/6, minSdk 24).
- **Framework:** NoobCrypt / NoobDev (misma familia que AR PRO). El cifrado
  vive en `libovpn3.so` (en `config.arm64_v8a.apk`; la base no trae `.so`).
  Otras nativas en ese split: `libgojni.so` (35 MB), `libnoobudp.so`,
  `libnoobzicore.so`, `libdns.so`, `libwg-go.so`, `libmmkv.so`,
  `libconscrypt_jni.so`, `libtun2socks.so`, `libtun2socksv.so`,
  `libpdnsd.so`, `libhev-socks5-tunnel.so`, `libdatastore_shared_counter.so`,
  `libtoolChecker.so`, `libwg.so`, `libwg-quick.so`.

## Cobertura previa en el repo

Re-clonado sparse (`feat/nuevas-integraciones`): el repo **no** tiene
proveedor/catálogo para XUI, pero **sí** cubre el formato de archivo
`.xui`: `decoders/Python/xui.py` (envoltorio de `_noobcrypt.py`) y la
entrada `"xui"` en `decoders.json`. El `_noobcrypt.py` del repo cubre el
índice 0 (GCM) y el índice 1 (CBC) con la misma clave de 32 B, pero **no**
maneja los valores CBC del índice 1 dentro de los tweaks (Name/Info) ni
el índice 5 (XTS) del catálogo. Este trabajo cierra esas dos brechas.

## Catálogo (XUI_Tunnel.py)

**Petición exacta de la app** (`C2106fy.a`, llamada desde
`RunnableC3622s1` caso 10):

```
GET https://deeptun.xyz/api/app?json=fb05d52c82789ba38e2a
```

- GET plano con `HttpURLConnection`, sin cabeceras propias (solo el
  User-Agent por defecto de la plataforma), sin autenticación ni
  parámetros; connect/read timeout 8,000 ms; exige HTTP 200; el cuerpo
  se lee línea a línea y se concatena. Si la URL no empieza por
  `http://` o `https://`, se le antepone `https://`. En caso de error
  la app reintenta una vez con `https://backup.com.link`.
- El cuerpo es una línea de Base64 estándar (914,852 B en vivo).
- Descifrado del cuerpo — `NoobCrypt.b(cuerpo, 5, false)`:
  Base64 → tweak (IV) = primeros 16 B, ciphertext = resto;
  **AES-256-XTS**, clave `KEY_CONFIG5` (64 B), robo de texto cifrado
  (CTS, IEEE 1619) en el último bloque parcial.
- El JSON resultante trae `Version`, `Message`, `DefUpdateURL`,
  `updater`, `updatemsg`, `cardMessage`, `cardLink`, `defTime`,
  `addTime`, `bonus`, `versioncode`, `Servers[]` y `Tweaks[]`.
- **Cada valor string del JSON va cifrado a su vez:**
  - Campos de nivel superior y `Servers[]` (incluido el `V2ray`
    anidado: UUID/Path): `NoobCrypt.b(valor, 0, false)` =
    Base64(nonce[12] + ct + tag[16]), **AES-256-GCM**, `KEY_FIELD`.
  - `Tweaks[]` (Name, Info, Sni, Payload, ProxyHost, ProxyPort,
    DNSHost, v2rayjson, …): `NoobCrypt.b(valor, 1, false)` =
    Base64(IV[16] + ct), **AES-256-CBC**, `KEY_FIELD`, PKCS#7.
    El `Flag` de los tweaks (`NOOB_DEV`) es texto plano.
- El catálogo no etiqueta servidores gratis/premium: cada servidor
  trae `NoobLevel` (0 o 1) y `AutoLogin`. Se reportan ambos conteos
  sin afirmar un reparto de pago.
- Protocolos (`XUITunnelMain.r0()`): 0 OVPN, 1 SSH, 2 SLOW DNS, 3 UDP,
  4 V2Ray, 5 WIREGUARD.

**Claves** (constantes públicas del formato, recuperadas de
`libovpn3.so`; NO son credenciales de cuenta):

- `KEY_FIELD` (32 B, índices 0/1/3/4): XOR plano de dos trozos de
  `.rodata`, verificado byte a byte contra `KEYS["xui"]` del repo:
  `file[0x21e240:0x21e250] ^ file[0x1c2b80:0x1c2b90]` ||
  `file[0x21e250:0x21e260] ^ file[0x1c2860:0x1c2870]`
  → `721d60cba2999a7e0f90e848d1ea31b7d06aa6be3654821fc4a5b388e70fc51c`
- `KEY_CONFIG5` (64 B, índice 5, AES-256-XTS): cuatro trozos de 16 B,
  cada uno ROL6(trozo_a XOR trozo_b) por byte
  (ROL6 = rotación izquierda de 6 bits):
  K0 = ROL6(`file[0x21e490:0x21e4a0]` ^ `file[0x1c2000:0x1c2010]`),
  K1 = ROL6(`file[0x21e4a0:0x21e4b0]` ^ `file[0x1c21c0:0x1c21d0]`),
  K2 = ROL6(`file[0x21e4b0:0x21e4c0]` ^ `file[0x1c2aa0:0x1c2ab0]`),
  K3 = ROL6(`file[0x21e4c0:0x21e4d0]` ^ `file[0x1c2ab0:0x1c2ac0]`)
  → `75dd40d75d069f98ddea21fe877ee6c9a82618a6c984f450f06f2e3e1e7e03`
  `06d37ce7ffed346eef5d0b3f7dece5c4bb7b86f24199fc21ccde99153c1a1ba799`
- Ambas claves se confirmaron ejecutando el `NoobCrypt.b` nativo en
  `libovpn3.so` bajo Unicorn y capturando la clave que se pasa a
  `EVP_DecryptInit_ex`; el descifrado XTS en Python puro reproduce el
  texto plano nativo byte a byte. (Detalle: K2 usa B2^R2; un primer
  intento con R0^R2 falló — el `ldp q4, q2, [x0, #0x20]` en 0x47b94c
  sobrescribe v4 con B2 antes del `eor`.)

**Otros índices NoobCrypt** (de `libovpn3.so`, por completitud):
0 AES-256-GCM, 3 ChaCha20-Poly1305, 1/4 AES-256-CBC, 5 AES-256-XTS,
resto ChaCha20. Cabecera: índices 0/3 → nonce 12 B + tag últimos 16 B;
resto → IV primeros 16 B.

**Cadenas ofuscadas:** LSParanoid K30 (`defpackage.K30`/`J30`, caso 0:
`java.util.Random` sembrado con `longs[0]`, XOR de cada long con
`nextLong()`, bytes little-endian, sin ceros finales). Port a Python
verificado contra el vector `getSystemService` → `"connectivity"`;
7,547 expresiones reemplazadas en `work/jadx-out-deob/` (mapa en
`work/k30_mapping.json`). El `paranoid-deobfuscator` 3.0.2 de referencia
falla en este APK (`extract-chunks`: más de un método get-string).

## Prueba en vivo (2026-11-14)

```
GET https://deeptun.xyz/api/app?json=fb05d52c82789ba38e2a
→ HTTP 200, 914,852 B, ~1.5 s
  SHA-256 72e52bc3786804def2fc3c260c8290648c341319c34bc344027c999b8a47c6a0
→ JSON descifrado: 686,123 B, Version 1.2.82
  (la seed del APK trae 1.0.1; DefUpdateURL coincide con la URL pedida)
  defTime 30, addTime 300, bonus 300
  47 servidores: NoobLevel 0: 27, NoobLevel 1: 20
    protocolos: 17 OVPN, 16 V2Ray, 5 UDP, 5 SLOW DNS, 4 SSH
    16 con sección V2ray; 31 con AutoLogin true, 16 false
  680 tweaks: 370 con Payload, 379 con SNI, 367 con ProxyHost/ProxyPort
    44 con v2Sni, 26 con v2rayjson, 57 con DNSHost
    modos: 3: 263, 2: 242, 5: 68, 6: 55, 8: 36, 7: 15, 4: 1
    todos con Flag "NOOB_DEV"
  3,618 valores string descifrados, 0 fallos
  (los 1,360 valores no vacíos que quedan tal cual son solo Flag
  "NOOB_DEV" y TweakId hex, ambos texto plano)
```

La comprobación del actualizador de la app es aparte (`M7` caso 17):
GET a `updater` (por defecto
`https://jezvpn.xyz/api/app?json=d154dff4627f2474cf87`) → HTTP 200,
1,241 B, `update_version: "1.31"`, con reglas solo para `com.jpro.vpn`
(última 16) y `noob.segou.vpn` (última 15) — **no** para
`com.xui_tunnel`, así que no hay actualización de app para XUI.
Mismo host que el catálogo de AR PRO, distinto token `json`.

## Archivos .xui (XUI_Tunnel_archivos.py)

- La app abre `.xui` por intent VIEW (`ImportActivity`, esquemas
  `content`/`file`, mimeType `*/*`, pathPattern `.*\.xui`). El archivo
  se lee línea a línea y se concatena sin saltos de línea.
- Formato: una línea Base64 → IV[16] + ct → **AES-256-CBC**,
  `KEY_FIELD`, PKCS#7 (`NoobCrypt.b(contenido, 1, false)`).
- El texto plano debe empezar por el nombre de la app,
  `XUI Tunnel VPN` (si no, la app muestra "Invalid config: does not
  belong to this app"); el JSON sigue inmediatamente, sin separador.
- Campos que aplica la app (`XUITunnelMain.H` / `G`): `ExpireDate`
  (ms epoch, 0 = sin caducidad), `RootBlock`, `DeviceID` (ids
  separados por `;`), `MobileData`, `PSInstall`, `isMsg`,
  `CFGMessage`, `NoobDev`, `SNIHost`, `Payload`, `ProxyHost`,
  `ProxyPort`, `useOvpnServer`, `useSshServer`, `serverDnsMode`,
  `TlSVersion`, `DNSHost`, `UDPhost`, `UDPobfs`, `UDPauth`,
  `UDPDownMbps`, `UDPUpMbps`, `isPassON`.
- **Sin esquema URI propio** (no hay `xui://`): el manifiesto no
  define ningún esquema de texto. Los servidores del catálogo traen
  enlaces `vless://` estándar como valores descifrados; esos
  protocolos ya están cubiertos por SP-DECODE.
- **Estado: SIN VERIFICAR contra un .xui real.** El método CBC y el
  prefijo del nombre de la app están verificados desde el APK
  (Java descompilado + NoobCrypt nativo) y con un vector de prueba
  (`--self-test`), pero no existe aún ningún `.xui` exportado real.

## Uso

```bash
# Catálogo en vivo (URL por defecto)
python3 XUI_Tunnel.py --url -o catalogo.json

# Catálogo desde un archivo local (Base64 crudo o JSON ya descifrado)
python3 XUI_Tunnel.py --file respuesta.txt -o catalogo.json

# Autoprueba con la seed real del APK (versión 1.0.1, 1 servidor, 1 tweak)
python3 XUI_Tunnel.py --self-test

# Archivo .xui
python3 XUI_Tunnel_archivos.py --file perfil.xui -o perfil.json
python3 XUI_Tunnel_archivos.py --self-test
```

Ambos scripts son **stdlib puro** (AES-256, GCM, CBC y XTS
implementados en Python con T-tables, verificados contra PyCryptodome
y el vector FIPS-197; el `--url` en vivo tarda ~3 s). No necesitan el
APK en tiempo de ejecución: el seed del APK va incrustado en
`XUI_Tunnel.py` (`SEED_BLOB`) y el vector `.xui` de prueba en
`XUI_Tunnel_archivos.py` (`TEST_VECTOR`).

## Entregables

- `XUI_Tunnel.py` — SHA-256
  `722e79e9226fad1ad5e2d5db0ea43551eeb078f2fdc9f944c0e322dae28933f8`
- `XUI_Tunnel_archivos.py` — SHA-256
  `bdde24ec67c995425f067c80d757e467f8ffbae85c410b5c8132936747e43dbb`
- `XUI_Tunnel.png` — 512×512, SHA-256
  `5b718f5223a8d329148b7ac084b2db156449024040b154be45acdbe4eb0c4292`
  (del `icon.png` 500×500 del XAPK)
- `README.md` (este archivo)
- `apk/` — base + splits extraídos, `icon.png`, `manifest.json`
- `work/` — análisis: `jadx-out/` y `jadx-out-deob/` (7,547 strings
  K30 desofuscadas), `k30.py`, `k30_mapping.json`, `xui_native.py`
  (harness Unicorn con los stubs de libc/pthread que hicieron falta),
  `aes_pure.py` / `aes_fast.py` (AES puro verificado),
  `live_response.txt` (cuerpo vivo, 914,852 B),
  `live_decrypted.json` (catálogo descifrado, v1.2.82),
  `live_fields.json`, `live_servers_tweaks.json`,
  `noobdev_decrypted.json` (seed, v1.0.1), `updater_response.json`,
  `test_xui_vector.txt` / `test_xui_plain.json`.

## Pendiente

- Un archivo `.xui` real exportado por la app (para verificar el
  decodificador extremo a extremo; hoy solo hay round-trip contra el
  método verificado).
- Si el servidor rota la clave o la URL, el script falla con un error
  honesto (`DECRYPT_FAILED` / `LIVE_DECRYPT_FAILED`) y habrá que
  re-analizar `libovpn3.so`.

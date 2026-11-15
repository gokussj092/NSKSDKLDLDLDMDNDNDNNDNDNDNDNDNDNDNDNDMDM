# SN VPN 5.0.7 — catálogo y archivos .sn

- **App:** SN VPN, `com.snnombre.snvpn`, 5.0.7 (versionCode 507), minSdk 23.
  APK proporcionado por Pedro (74.426.552 B, SHA-256
  `a9f4936bb2a9c2da2b124a4b8fa10d53a0bd1ba3a7839bd70dffcd24811b4006`).
  Sin cobertura previa en el repo SP-DECODE (86 apps, rama
  `feat/nuevas-integraciones`).
- **Librerías nativas:** libgojni.so (Go/Xray), libhysteria.so, libhysteria1.so,
  libv2ray.so, libhev-socks5-tunnel.so, libtun2socks.so, libdnstt.so,
  libdatastore_shared_counter.so — en arm64-v8a y armeabi-v7a dentro del APK
  único. 3 dex. Assets: about.txt, flags, geoip.dat, geosite.dat.

## Catálogo en vivo

Endpoint exacto de la app (`data/network/a::a`, HttpURLConnection, GET, sin
cabeceras, timeouts 10 s):

```
GET https://raw.githubusercontent.com/SINNOMBRE22/Fallas/main/online.json
```

Cifrado (`I0/a::a`, el "StringCrypter" de la familia):

```
cuerpo = texto invisible U+2000..U+200F (portador nibble, 2 chars = 1 byte)
Base64 = nibble(carrier)
JSON   = AES-256-CBC(Base64, key, IV = 16 ceros, PKCS#7)
key    = SHA-256(hexadecimal en mayusculas de "ARABIR")
       = SHA-256(b"415241424952")
       = 20ffeeb0f381a71025943a057eee79bbc51823d13c560d5c8e81a604ce042439
```

**Resultado en vivo (2026-11-14, descarga real, verificado con este script):**
`online.json` es la **Version 4.0 con TODAS las listas vacías** (Servers, SSH,
Networks, SSLNetworks, UDPCustom, DNSTT, V2RAYCustom, BHTTP). El vendedor
vació el catálogo; el script lo reporta como catálogo vacío y no inventa
servidores. SHA-256 del cuerpo en vivo:
`ede91b1e455c67bc8f5364981825152bc954396fbcfdf005865645d30ee57391`.

El mismo método abre el segundo archivo del mismo repositorio, que la app
5.0.7 **NO descarga** (no hay ninguna referencia a él en el DEX; puede ser de
otra versión de la app o de otra app del mismo autor):

```
GET https://raw.githubusercontent.com/SINNOMBRE22/Fallas/main/online_v2.json
```

**online_v2.json en vivo: Version 2.0.27, formato v2, 25 configs, todas FREE**
(21 SSH, 1 HYSTERIA, 1 ZIVPN, 1 SLOWDNS, 1 BHTTP; 21 con Payload, 21 con
SNIHost; todas de México, host principal mex.sinnombre.xyz:443). SHA-256 del
cuerpo en vivo: `5fdd1864b08d172973d578c3f89baef5be887d7f616e9ffbde006fbcd295df9f`.
Nota del catálogo: "servidores free No olvides apoyar la app".

Los otros dos archivos del repositorio (`cfg_b69n7avsse8xg0_v2.dat`,
`supra_vpn.dat`) **no** abren con esta clave (padding inválido); no pertenecen
al catálogo de SN VPN 5.0.7.

## Archivos .sn

Formato verificado en el DEX (`SnSecureCodec` = `data/custom/v`,
`SnFileImporter` = `data/network/j`) y confirmado con el archivo real de
Pedro `esvin11_3_0mc8.sn` (5.088 B, SHA-256
`13bae3eb7e279183e0906c9258d5cd704cc7fb6b201efbca25c0482264916f4c`):

```
.sn    = texto invisible U+2000..U+200F
Base64 = nibble(carrier)
SNX2   = Base64: "SNX2" + version(2) + flags + salt(16) + nonce(12)
         + AES-256-GCM(AAD = cabecera de 6 B) + tag(16)
JSON   = zlib-inflate(AES-GCM)
```

Flags del byte 5: bit 0 = con contraseña, bit 1 = ligado a dispositivo.
Derivación de la clave (`SnSecureCodec::a`):

```
master[i] = B[i] ^ C[i] ^ ((i*31+7) & 0xFF)     (B y C constantes del DEX)
k1 = HMAC-SHA256(master, "SNVPN-FILE-KEY-v2" || salt)
si hay contraseña: T = PBKDF2-HmacSHA256(pwd, salt, 12000, 32)
                   k2 = HMAC-SHA256(k1, "PWD" || T)
si hay HWID:       k3 = HMAC-SHA256(k2, "HWID" || HWID en mayúsculas [A-Z0-9])
HWID = "snvpn:" + SHA-256(android_id)
```

**El archivo real de Pedro abre sin contraseña y sin HWID** (flags = 0), como
él dijo. Perfil: **"esvin11"**, protocolo **BHTTP**, host **192.6.154.99:8080**,
usuario **esvin11**, creador "GAELITO GT😎".

La app también acepta JSON en claro y enlaces estándar (vmess://, vless://,
trojan://, ss://, hysteria2://, hy2://, hysteria://) por pegado de texto.
**Sin esquema URI propio:** el manifest solo registra VIEW/SEND con scheme
content/file y mimeType `*/*` para importar archivos .sn.

## Archivos

- `SN_VPN.py` — catálogo v1 (ServerConfig) y v2 (Configs). CLI
  `--url/--file/--stdin/--self-test/-o/--json`. `--url` sin valor usa
  online.json. `--self-test` 8/8 OK.
- `SN_VPN_archivos.py` — decodificador `.sn` (y constructor `--encode` para
  pruebas). CLI `--file/--stdin/--password/--hwid/--android-id/--self-test/
  -o/--json`. `--self-test` 11/11 OK, incluido el vector de derivación del
  archivo real.
- `SN_VPN.png` — 512×512, logo de la app.
- `catalog_online.json` — cuerpo en vivo de online.json (1.536 B).
- `catalog_online_decoded.json` — JSON descifrado (v4.0, vacío).
- `catalog_online_v2.json` — cuerpo en vivo de online_v2.json (157.056 B).
- `catalog_online_v2_decoded.json` — JSON descifrado (v2.0.27, 25 configs).
- `esvin11_3_0mc8.sn` — archivo real exportado por la app (abre con
  `SN_VPN_archivos.py --file esvin11_3_0mc8.sn`).

## Uso

```bash
python3 SN_VPN.py --url
python3 SN_VPN.py --url https://raw.githubusercontent.com/SINNOMBRE22/Fallas/main/online_v2.json
python3 SN_VPN_archivos.py --file esvin11_3_0mc8.sn
python3 SN_VPN_archivos.py --file archivo.sn --password SECRETO
python3 SN_VPN_archivos.py --file archivo.sn --android-id 0123456789abcdef
```

## Pendientes

- Un `.sn` real con contraseña y/o ligado a dispositivo para validar extremo a
  extremo esas dos ramas (la derivación está verificada por construcción y por
  round-trip, pero no hay muestra real con flags 1 o 2).
- Si el vendedor vuelve a llenar online.json, el catálogo v1 se abrirá con
  este mismo script sin cambios.

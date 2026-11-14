# PNT VPN — decodificador del catálogo

App: **PNT VPN**, `com.pntvpn.net`, **1.2.8 (versionCode 28)**, minSdk 23.
Versión de Google Play (actualizada 8 nov 2026), verificada en el APK de
APKPure: XAPK 44.488.808 B, SHA-256
`125d2aaf31be126bdd1da3fdc357b125417110403547a65b7aff9c8cde93f909`
(base + `config.arm64_v8a` + `config.en` + `config.mdpi`).
Sin cobertura previa en el repo SP-DECODE (rama
`feat/nuevas-integraciones`, 86 carpetas de apps, ninguna de PNT;
verificado por clon sparse el 2026-11-14).

## Método (verificado en vivo 2026-11-14)

**Etapa 1 — índice** (la app lo pide con Volley `JsonObjectRequest` GET,
sin cabeceras propias, a la URL de `NativeSec.getApiUrl()`):

```
GET https://raw.githubusercontent.com/sansoe2022/new_pntvpn/refs/heads/main/v28Api.json
```

→ JSON `{"version": 32, "message": ..., "fileUrl": "<url del catálogo>",
"messageWarning": ..., "title": ..., "link": <Play Store>,
"website": "https://pntvpn.netlify.app/", "versionCode": 28}`.
Si la versión guardada es menor que `version`, descarga el catálogo.

**Etapa 2 — catálogo** (la app lo descarga con PRDownloader, GET plano
sin auth, a `<filesDir>/SVPN/Config.json`; si no existe, lee el asset
`pntvpn.json`):

```
GET https://raw.githubusercontent.com/sansoe2022/new_pntvpn/refs/heads/main/v28Config
```

→ cuerpo: una línea Base64 estándar → Base64 → **XXTEA** (clase
`SVPNDex`, DELTA fijo `-772015605` = `0xD1FBFA0B`, clave =
`NativeSec.getAesKey()` = `pntvpn4455`) → JSON con `FileName`,
`InterUnit`, `RewardUnit`, `premiumKey`, `BannerUnit`, `OpenAppUnit`,
`WebUrl`, `ContactUrl`, `FacebookUrl`, `TelegramUrl`, `BgUrl`,
`Servers`, `HTTPNetworks`, `SSLNetworks`, `Ovpn_Cert` (plantilla
OpenVPN en texto plano).

**Campos cifrados** de cada servidor/red (`FileUtils.showJson`):

```
Base64 -> XXTEA (clase XxTea, DELTA = NativeSec.getDelta() = 0x3B2959AF,
                 clave = FileUtils.getPass() = "5741")
       -> texto UTF-8 con caracteres portadores (U+2C00-U+2DFF)
       -> cada caracter -= 5741, dos veces (De2.decryptString x2)
       -> texto plano
```

Campos: `ServerIP`, `ServerCloudFront`, `ServerHTTP`, `V2ray`,
`SlowIP`, `PublicKey`, `Username`, `Password`, `NetworkPayload`,
`SquidProxy`, `WSHost`, `Address`, `NetworkFrontQuery`,
`NetworkBackQuery`.

**Contador en línea** (`ServerStatus`/`ServerCount`, Volley
`StringRequest` GET plano al campo `Info` de cada servidor):

```
GET http://<host>:81/server/online_app   ->  {"onlines": "64", "limite": "2500"}
```

**Valores nativos** (`libnative-sec.so`, arm64, recuperados emulando los
JNI con Unicorn; el `.so` también guarda dos cadenas hex de 64 caracteres
en `.rodata` que `getDelta` usa para una comprobación anti-manipulación,
no necesarias para decodificar):

| Función | Valor |
|---|---|
| `getApiUrl()` | la URL de `v28Api.json` |
| `getAesKey()` | `pntvpn4455` (clave XXTEA del catálogo) |
| `getAuthHash()` | `5741` (clave XXTEA de los campos) |
| `getDelta()` | `0x3B2959AF` (DELTA de `XxTea`) |

Las librerías nativas están todas en `config.arm64_v8a.apk` (la base no
tiene `.so`): `libdns.so`, `libgojni.so`, `libh1.so`, `libmmkv.so`,
`libnative-sec.so`, `libovpncli.so`, `libovpnudp.so`, `libpdnsd.so`,
`libtun2socks.so`. La app es un fork de v2rayNG (servicios
`com.v2ray.ang.*`) con túneles SSH/UDP/OpenVPN propios.

## Resultado en vivo (2026-11-14)

- API **version 32**, `FileName` **v28Config**.
- **8 servidores, todos gratuitos** (Category 0): 3 Singapore
  (`free6/7/8june.sksvpn.shop`) + 5 Thailand
  (`free16/17/3/4/5june.sksvpn.shop`). SSH 22, SSL 443, proxy 8080;
  cada uno con enlace `vless://` por WebSocket en el puerto 8080 y
  credenciales SSH propias (el script las descifra; el resumen no las
  imprime).
- **12 redes HTTP, 9 con payload** (1 config JSON de Hysteria + 8
  payloads HTTP injector con `[crlf]`/`[split]`/`[host]`/`[ua]`), **0
  redes SSL**.
- En línea verificado en vivo: SG-1 64/300, SG-2 32/300, SG-3 20/300,
  TH-1 220/300, TH-2 174/300, TH-3 151/300, TH-4 102/300, TH-5 109/300.
- El asset incluido en el APK (`pntvpn.json`, `FileName` "newConfig")
  abre con el mismo método: 8 servidores y 11 redes (le falta la red
  "Star Link" del vivo).

## Archivos

| Archivo | Descripción |
|---|---|
| `PNT_VPN.py` | Catálogo + campos. `decode()` + `run()` + CLI `--url` / `--config-url` / `--file` / `--online` / `--self-test` / `-o`. Solo stdlib. |
| `PNT_VPN.png` | Icono 512×512 (del XAPK). |
| `catalog_sample.b64` | Cuerpo vivo de `v28Config` (37.304 B, SHA-256 `35931ef5…`). |
| `pntvpn.json` | Asset incluido en el APK (36.604 B, SHA-256 `89173bf0…`). |

`PNT_VPN.py` SHA-256: `942665ab745125a2679e0865c8321d8d2028ee85aa96abcb7469bdb5f740b9e9`.

## Uso

```bash
python3 PNT_VPN.py --url              # API + catálogo en vivo
python3 PNT_VPN.py --url --online     # + usuarios en línea por servidor
python3 PNT_VPN.py --config-url <URL> # catálogo directo, sin etapa 1
python3 PNT_VPN.py --file Config.json # cuerpo guardado (Config.json o pntvpn.json)
python3 PNT_VPN.py --self-test        # round-trip + ambas muestras (11 pruebas)
python3 PNT_VPN.py --url -o out.json  # guarda el catálogo descifrado
```

## Formato de archivo / esquema URI

**No hay formato propio de archivo de perfil ni esquema URI de texto.**
El manifiesto solo declara `MAIN`/`LAUNCHER` (sin `ACTION_VIEW` ni
esquemas); la app importa enlaces estándar `vmess://`/`vless://`/
`trojan://`/`ss://` por portapapeles (como el fork de v2rayNG que es) y
su único "archivo" es el catálogo mismo (`SVPN/Config.json` o el asset
`pntvpn.json`), que abre `PNT_VPN.py --file`. No hay archivos `.sks`.
Por eso no hay `PNT_VPN_archivos.py` separado.

## Pendiente

- Confirmación de extremo a extremo con un `Config.json` real
  descargado por la app en un teléfono (el método ya está verificado
  contra el cuerpo vivo y el asset, pero el archivo que la app guarda
  es el que cerraría el ciclo).
- Si el servidor rota la clave (como pasó con RNV/AT NET), el síntoma
  sería `XXTEA` en `--url`: habría que re-analizar `libnative-sec.so`
  (los valores salen emulando los 4 JNI con Unicorn; ver
  `work/emu_native.py`).

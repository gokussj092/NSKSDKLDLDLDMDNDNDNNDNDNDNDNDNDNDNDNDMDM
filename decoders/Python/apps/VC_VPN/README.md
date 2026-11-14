# VC VPN — decodificador de catálogo y archivos para SP-DECODE

App: **VC VPN** — `com.vc.vpn`, versión **8.0** (versionCode **80**, minSdk 32),
versión pública de Google Play (actualizada 7 nov 2026). APK verificado por
manifest: XAPK de APKPure, SHA-256
`6e7965f632bfbb40f97ca2b89cac91bc66f5b38367f99fbacdf4f65036361c65`.

**Sin cobertura previa en el repo SP-DECODE.** Verificado 2026-11-14:
`decoders/Python/apps/` (86 carpetas) no tiene ninguna entrada VC, y la
búsqueda de `com.vc.vpn` en el repo devuelve 0 resultados. Es un app
tekidoer (misma familia que Guruz Tunnel, batch 8), pero con sus propias
claves, su propio prefijo (`VC` en vez de `GT`) y su propio catálogo.

## Catálogo

```
GET https://raw.githubusercontent.com/guruzgh-ed/conf/refs/heads/main/vc.js
```

GET plano (HttpURLConnection), sin autenticación, sin parámetros ni
cabeceras propias más allá del User-Agent de la plataforma
(`Dalvik/2.1.0 (Linux; U; Android 14)`). GitHub lo sirve para cualquier
User-Agent; verificado en vivo con urllib y con el script.

- Cuerpo: una línea `STGCM3.VC.<b64url(IV 12 B)>.<b64url(ct + tag 16 B)>`
- Cifrado: **AES-256-GCM**, clave `KEY_CONFIG3`, AAD = `b"STGCM3.VC."`
  (el prefijo de 10 bytes, con el punto final).
- Existe la variante legacy `STGCM2.VC.` (misma forma, clave
  `KEY_CONFIG2`); el script acepta ambas.
- El JSON descifrado trae `version`, `schema_version`,
  `config_revision`, `url_updater` (el mismo `vc.js`, para la siguiente
  actualización), `minimum_app_version`, `force_update`, `Servers[]`
  y `Tweaks[]`.
- Cada valor de cadena del JSON lleva una codificación propia:
  - **r95**: ofuscación por carácter (`i%4==0` XOR `0x57712`,
    `i%4==1` XOR `0x5a0c38d7`, `i%4==2` XOR `0xA25A5826`, `i%4==3`
    NOT; todo a 16 bits, auto-inversa). Se detecta por el alfabeto
    ofuscado (U+3800–U+38FF, U+5800–U+58FF, U+7000–U+7FFF,
    U+FF80–U+FFDF) y solo se acepta si el decode no deja ningún
    carácter de ese alfabeto. Los pares sustitutos UTF-16 (emoji) se
    combinan en su punto de código real.
  - **`u8:` + Base64** (campos de mensaje).
  - **`VCCR1.<b64url(IV 12 B)>.<b64url(ct + tag 16 B)>`**: AES-256-GCM,
    clave `KEY_CRED`, AAD = `b"VCCR1."` (credenciales, detalles UDP,
    Payloads de tweaks).

### Claves

Claves públicas de formato de la app (constantes, NO credenciales de
cuenta), recuperadas de `libfrkudp.so` (todo en `config.arm64_v8a.apk`;
la APK base no tiene ninguna `.so`). Cada clave se deriva de un blob de
32 bytes en `.rodata` como
`key[i] = blob[i] XOR 0xa7 XOR ((base + 73*i) & 0xff)`:

| Clave | Blob `.rodata` | base | Valor |
|---|---|---|---|
| `KEY_CONFIG3` (STGCM3) | `0x44d30` | `0x51` | `9abd5c173bddce3230bb429bf22c00c2730c9895015d3e568b459112efaa91be` |
| `KEY_CRED` (VCCR1) | `0x44d50` | `0x71` | `76f5a6e1cdeb1aa1c17665736dc8a290e6c0a6620700c42b2f6033d5ce87e5cf` |
| `KEY_CONFIG2` (STGCM2) | `0x44d70` | `0x5d` | `8a759c0e65b3126fac63995288f035f6fd58dd59cd7ecc5595e097f17a48a617` |

Las funciones de derivación están en `libfrkudp.so` en `0xd7224`
(base `0x51`), `0xd7540` (base `0x71`) y `0xd5850` (base `0x5d`).
Verificadas por descifrado en Python puro del seed incluido en el APK
(`zf1.l1I1Il1`) y del catálogo en vivo (los tags GCM verifican).

### Resultado en vivo (2026-11-14, `VC_VPN.py --url`)

- HTTP 200, **381.999 bytes**, SHA-256
  `fef0820b259d05feb31659aade9e2be5abc0c1d95c4c96892d8a60fa42c600ab`
- Catálogo **versión 1.4**, `schema_version` 2, `config_revision` 15,
  `minimum_app_version` 79, `force_update` true.
- **19 servidores, los 19 PREMIUM, 0 gratis.**
- **634 tweaks, 311 con Payload.**
- **340 valores `VCCR1.`**, todos descifran (0 fallos);
  **1.966 valores r95**, todos decodifican (0 fallos).
- Descifrado completo en ~16 s en Python puro.

La app es la misma familia que Guruz Tunnel pero con catálogo propio:
Guruz usa `gt.js` (v1.1, 76 servidores); VC VPN usa `vc.js` (v1.4,
19 servidores). No se comparten servidores ni tweaks.

## Archivos

| Archivo | SHA-256 | Descripción |
|---|---|---|
| `VC_VPN.py` | `8c5cee33ff25ee6c0db6fbdfe81336b35258f13740f67341155c261f1c3ef98d` | Catálogo: `decode()` + `run()` + CLI `--url`, stdlib puro. |
| `VC_VPN_archivos.py` | `3b46999aefb76c1e45a9b892573248a3eb360a125ce000c66a5f1b559825152d` | Archivos `.tgv` y `.vcv` (ver abajo). Importa de `VC_VPN.py`; mantener juntos. |
| `VC_VPN.png` | `61901a0e7089713fd0f054ec55ffb567a2a88ab976418d1c75c15314bc68ec58` | Icono 512×512 (copia directa del `icon.png` del XAPK). |
| `catalog_sample.b64` | `fef0820b259d05feb31659aade9e2be5abc0c1d95c4c96892d8a60fa42c600ab` | Cuerpo cifrado real del catálogo en vivo (v1.4), para `--file` / `--asset`. |

### .tgv — SÍ, decodificador completo

La app lo abre con un intent-filter `VIEW` en MainActivity (esquemas
`file`/`content`, `mimeType */*`, `pathPattern .*.tgv`). Un archivo
`.tgv` es un texto con un sobre `STGCM2.VC.` / `STGCM3.VC.`, el mismo
sobre del catálogo: al abrirlo sale el JSON (catálogo completo o un
perfil suelto) con los valores ya decodificados (r95 / `u8:` / `VCCR1.`).

```bash
python3 VC_VPN_archivos.py --file perfil.tgv -o perfil.json
python3 VC_VPN_archivos.py --file catalog_sample.b64   # el catálogo vivo como .tgv
```

Verificado con round-trip sintético (STGCM3 + STGCM2) y con el cuerpo
real del catálogo v1.4 como archivo `.tgv`.

### .vcv — PENDIENTE (reportado, no inventado)

La app **exporta** perfiles a `Documents/<nombre app>/<nombre>.vcv`
(ExportActivity): el contenido es la salida cruda de
`TekProtect.nEncryptUserConfig(JSON {"VCV_CONFIG": <perfil>})`. Ese
sobre vive en la librería nativa (`nEncryptUserConfig` /
`nDecryptUserConfig`, `0xdab60` / `0xdbe00` en `libfrkudp.so`), con
blobs `.rodata` propios (`0x44d90` / `0x44e90`) detrás de `std::string`
de libc++. **No se pudo resolver offline**: no existe ninguna muestra
real de `.vcv` y la emulación Unicorn del descifrador se atasca en
libc++ (`basic_stringbuf::str`). `VC_VPN_archivos.py` detecta un
`.vcv` y lo reporta como `VCV_PENDING` con su SHA-256 y tamaño, sin
inventar contenido. Con una muestra real de `.vcv` exportada por la
app se podrá completar el método.

No hay archivos `.sks` (la app no los usa).

## Textos (enlaces)

La app **no declara ningún esquema URI propio** (no hay `vcvpn://` ni
similar; el manifest solo tiene el filtro VIEW de `.tgv`). Los
servidores del catálogo contienen enlaces estándar `vless://` /
`hysteria2://` como valores ya descifrados; esos protocolos ya están
cubiertos por SP-DECODE. No hay nada que incluir como esquema propio.

## Uso

```bash
python3 VC_VPN.py --self-test          # seed real del APK (v0.1, 1 servidor, 1 tweak)
python3 VC_VPN.py --url                # descarga y descifra el catálogo en vivo
python3 VC_VPN.py --url -o vc.json     # lo guarda en vc.json
python3 VC_VPN.py --file catalog_sample.b64
python3 VC_VPN_archivos.py --self-test
python3 VC_VPN_archivos.py --file perfil.tgv
```

## Qué falta (pendiente)

- Un archivo `.vcv` real exportado por la app, para resolver el sobre
  `nEncryptUserConfig` y completar el decodificador de `.vcv`.
- Un archivo `.tgv` real exportado/compartido desde un teléfono, para
  la confirmación end-to-end (el método ya está verificado con el
  catálogo vivo y con round-trip sintético).
- Si el servidor rota las claves o cambia el formato `STGCM3.VC.`,
  hay que re-analizar `libfrkudp.so` (las funciones de derivación
  están en `0xd5850` / `0xd7224` / `0xd7540`).

# Hex Custom 10.6.7 — análisis

**App:** Hex Custom 10.6.7, versionCode 107, package `com.hex.custom.jotchuast`
(minSdk 32, targetSdk 37). APK proporcionado por el propietario:
`Hex_Custom_10.6.7_0_jk34.apks` (base.apk + splits
`split_config.arm64_v8a`, `split_config.es`, `split_config.xhdpi`),
48.635.545 B,
SHA-256 `9b608c7f52b1d64aeed411c89d19f7dd8649b470920668c8978d080300c52deb`.
El APK no se guarda en el repo.

## Resultado

**El archivo `.hexcm` real de la nube ABRE completo sin contraseña.** La
rama sin contraseña (flags bit 0 = 0), que en 10.6.4 quedó sin verificar
por falta de muestra, se resolvió en esta versión: es la misma cadena
HMAC que la rama con contraseña pero sin el `argon2_key`. Verificado de
dos formas independientes: emulación JNI de `libhexvpn.so` 10.6.7
(`nativeOpen` 0x16170) y reproducción en Python puro byte a byte.

Archivo de prueba (propietario, descargado de la nube con la clave
`HexCustom-BoKo2Q5gQR`):
`FastDNS_nube_HexCustom-BoKo2Q5gQR_1_r6pe.hexcm` (6.958 B,
SHA-256 `ea016cb4a609e609bb66202f0ba1b0f1d5fe6a0f94eba2982327643be2e53d49`),
flags `0x00`:

| Campo | Valor |
|---|---|
| Perfil | FastDNS |
| serverType / tunnelType | 19 (FastDNS, nuevo) / -1 |
| Servidor | test.hexapps.app:53 (`fastdns_server`), puerto local 8080 |
| Usuario / contraseña | (vacíos) |
| fastdns_ovpn | config OpenVPN embebida (5.051 caracteres: `client`, `dev tun`, `proto udp`, `remote 127.0.0.1 8080`, `data-ciphers AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305`, `auth SHA512`, `compress lz4-v2`, CA incluida) |
| Empresa / país | OXXO CEL / mx |
| Bloqueado | true (blocked=true; blockRoot/blockCompany=false) |
| Expira | 0 (sin expiración) |
| Exportado | 1794853472138 ms (2026-11-16 18:24 UTC) |
| Firma | presente (64 hex) |

La **rama con contraseña no cambió**: el archivo 10.6.4
`NONE_BREAKER__0_0osx.hexcm` (7.054 B,
SHA-256 `7babe831f18dbd9822eca9fbf50ee51cd361a71310776ef0197bf3d9d97aca32`)
sigue abriendo con el decodificador nuevo y con la lib 10.6.7 emulada,
con JSON idéntico al del decodificador 10.6.4 (verificado en esta
entrega: comparación directa de ambos decodificadores, JSON idéntico).

## Qué cambió 10.6.4 → 10.6.7

### App / manifiesto

- versionCode 104 → 107; minSdk 24 → **32** (targetSdk 37 en ambas).
- Actividades 9 → 11, servicios 17 → 22. Nuevos: `FastDnsVpnService`
  (serverType 19, FastDNS: OpenVPN sobre DNS) y `LicenseActivity`
  (PairIP). Sin cambios en permisos (27).
- Filtros de intent **sin cambios**: `MainActivity` sigue con VIEW de
  `.*\.hex` y `application/octet-stream`; **no hay esquema URI propio**
  (no existe `hexcustom://`).
- Icono **sin cambios**: el foreground del APK 10.6.7
  (`res/mipmap-xxxhdpi-v4/ic_launcher.webp`, 2.566 B) es byte a byte el
  mismo que `res/sK.webp` de 10.6.4. Se reutiliza `Hex_Custom.png` (512×512).

### Librerías nativas (split `split_config.arm64_v8a.apk`)

Solo se distribuye arm64-v8a en el `.apks` (el APK 10.6.4 traía además
armeabi-v7a; eso es diferencia de empaquetado, no de la app).

| Librería | 10.6.4 → 10.6.7 |
|---|---|
| `libhexvpn.so` | CAMBIÓ (367.592 → 367.200 B; `nativeOpen` 0x131e0 → 0x16170; misma CONSTANTS32, mismos labels, mismos parámetros Argon2id) |
| `libkovsec.so` | CAMBIÓ (5.353.496 → 6.800.656 B) |
| `libkovsecvm.so` | CAMBIÓ (364.208 → 363.496 B) |
| `libfastdns-danaelh4.so` (4.021.784 B), `libfastdns-ovpn.so` (2.461.656 B) | **NUEVAS** (FastDNS) |
| `assets/protection/kov-sec.dat` | CAMBIÓ (619.749 → 2.150.154 B) |

### Contenedor HXS3 y criptografía

- **Sin cambios en el formato**: magic `HXS3`, versión 3, cabecera de
  58 B, AES-256-GCM exterior + XChaCha20-Poly1305 interior, AAD =
  cabecera en ambas capas.
- **Sin cambios en la rama con contraseña**: Argon2id
  (t=3, m=65536 KiB, p=1, v=0x13, 32 B) → `H1 = HMAC-SHA256(salt,
  CONSTANTS32 || argon2_key)` → `K_outer`/`K_inner` con los labels
  `HexVPN-server-v3-outer/inner` + paquete + `\x01`. Verificado con la
  lib 10.6.7 emulada sobre el archivo 10.6.4 (Argon2id con los mismos
  parámetros; JSON idéntico).
- **NUEVO — rama sin contraseña (flags bit 0 = 0)**: `H1 =
  HMAC-SHA256(salt, CONSTANTS32)` (sin `argon2_key`); `K_outer` y
  `K_inner` se derivan igual que antes. Es decir, la KDF es una sola:
  `H1 = HMAC(salt, CONSTANTS32 || argon2_key?)` donde el segundo
  término solo existe con contraseña. Capturado de la librería nativa
  10.6.7 emulada (función MIX 0x1992c, llamada dos veces: una por
  label) y reproducido en Python puro con los dos vectores conocidos
  del archivo FastDNS (salt `7bcf84404cea9732c306598b6a2fa3a1`):
  `K_outer = df372263…e1d2185`, `K_inner = c186bd78…1e28a12`.

## Método (contenedor HXS3, 10.6.7)

```
[0:4]   magic "HXS3"
[4]     version = 3
[5]     flags: bit 0 = 1 -> protegido con contrasena (Argon2id)
[6:22]  salt (16 B)
[22:46] nonce24 (24 B)  -> capa interna XChaCha20-Poly1305
[46:58] nonce12 (12 B)  -> capa externa AES-256-GCM
[58:-16] ciphertext (capa externa)
[-16:]  tag GCM (16 B)
AAD de AMBAS capas = los 58 primeros bytes del archivo (cabecera).
```

Derivación de claves:

```
CONSTANTS32 = 265943050e89ae3aa403ae988c62026ef378c66a9c69be529929d7d5d3d47f3d
              (constante fija de la app, libhexvpn.so .data.rel.ro;
               IDENTICA en 10.6.4 y 10.6.7)
CON contrasena: argon2_key = Argon2id(password, salt, t=3, m=65536 KiB, p=1, v=0x13, 32 B)
                H1 = HMAC-SHA256(key=salt, msg=CONSTANTS32 || argon2_key)
SIN contrasena: H1 = HMAC-SHA256(key=salt, msg=CONSTANTS32)
En ambos casos:
  K_outer = HMAC-SHA256(key=H1, msg="HexVPN-server-v3-outer" + PACKAGE + "\x01")
  K_inner = HMAC-SHA256(key=H1, msg="HexVPN-server-v3-inner" + PACKAGE + "\x01")
```

Descifrado:

```
intermedio = AES-256-GCM(K_outer, nonce12, ct, tag, AAD=cabecera)
plaintext  = XChaCha20-Poly1305(K_inner, nonce24,
                                ct=intermedio[:-16], tag=intermedio[-16:],
                                AAD=cabecera)
```

El plaintext es el perfil JSON (`version`, `server`, `meta`, `signature`).

## Bloqueo HWID: metadato, no cifrado

Verificado en esta entrega con 3 archivos reales de prueba
proporcionados por el propietario (perfil `bait`, servidor
`v2ray.halconr.com:443`, empresa BAIT, país mx; los archivos NO se
guardan en el repo y los valores de contraseña/HWID NO se registran):

| Archivo | Tamaño | SHA-256 | Variante | Resultado |
|---|---|---|---|---|
| `bait_0_xi2i.hexcm` | 1.398 B | `637333195e6b284cd2f36c82126029312df3858d266486ac35eff2a985fca4f2` | solo contraseña | Abre con la contraseña de prueba |
| `bait__2__1_2dc4.hexcm` | 1.368 B | `b20243a3f179929b40235367172ff2122b3bb210e0b116661587e5e41703d41e` | solo HWID | Abre **sin contraseña** (credenciales vacías): el descifrado no requiere el HWID |
| `bait__3__2_e9gx.hexcm` | 1.446 B | `f2b23c8460833811ffed99a9908a34bf19ec013483ec3c4afd4b6306c0c02eff` | contraseña + HWID | Abre con la contraseña de prueba |

Los 3 abren por la ruta del worker (`hex_custom_bridge.py` con el
decodificador nuevo). El bloqueo vive en `meta.blockId` /
`meta.blockIdValue` del JSON descifrado: no interviene en la
derivación de claves y no necesita código propio.

## Nube / catálogo / texto

- **No hay catálogo HTTP de proveedor ni lista de archivos.** La nube
  es Firebase Firestore: colección `archivos`, documento
  `HexCustom-<10 caracteres>`, campo `contenido` (bytes Base64 del
  `.hexcm`). Descarga por clave verificada **en vivo** (ver
  `CLOUD_DOWNLOAD.md`): `GET
  https://firestore.googleapis.com/v1/projects/hexcustom-d3bc9/databases/(default)/documents/archivos/HexCustom-BoKo2Q5gQR`
  → HTTP 200, documento con `contenido` (6.958 B),
  `nombre: FastDNS.hexcm`, `tipo: application/octet-stream`,
  `tamano: 6958`, `creado: 1794853479291`. El archivo descargado abre
  con la rama sin contraseña y es el mismo perfil FastDNS (re-exportado
  con otra salt: solo difieren `meta.exportedAt` y `signature`).
  **No hay broker**: no es un catálogo, es un buzón de archivos sueltos.
  La clave de API de Firebase NO se guarda en el repo: se pasa por CLI.
- **No hay esquema URI propio de texto.** El manifest solo declara el
  filtro VIEW de `.*\.hex` y `application/octet-stream`. No existe
  `hexcustom://`.

## Integración en el repo (esta entrega)

- `Hex_Custom_archivos.py` (10.6.4) queda **intacto**; se añade
  `Hex_Custom_10.6.7.py` con su nombre original (byte-idéntico al
  entregado, SHA-256
  `42af7f0d6187d9dc1437656c85c564c841c082ecbf62677493526c707bd0c0aa`).
- `hex_custom_bridge.py` ahora carga el módulo nuevo por ruta con
  `importlib` (el nombre de archivo contiene puntos `10.6.7` y no admite
  importación punteada). `Hex_Custom.py` (módulo de catálogo, FILE_ONLY)
  no se tocó.
- `manifest.json`: versionCode 107, versionName 10.6.7,
  `fileDecoder: Hex_Custom_10.6.7.py`.
- Entrada supplied `hex-custom`: versionCode 107, versionName 10.6.7,
  `fileModule: Hex_Custom_10.6.7.py`; resto igual (FILE_ONLY).
- `engine.py`: etiquetas/comentarios "Hex Custom 10.6.4" → 10.6.7.
- Icono `cloud/web/public/server-vpn-icons/hex-custom.png` (512×512,
  SHA-256 `d4282f169624e8393fd5f50b9a8fff2377e9be05e1ddcdaffe6a9d9b620b532e`):
  la entrada supplied ya lo referenciaba y **no existía en el repo**.
- `file-formats.json` no se tocó: el sufijo `hexcm` ya existe y cubre
  ambas apps por content dispatch.

## Auditoría HMAC

- Archivo: integridad local por tags AEAD (GCM + Poly1305) y HMAC-SHA256
  en la derivación de claves. No es autenticación de conexión VPN.
- Transporte / autenticación de conexión: NO_OBSERVED en este dossier;
  no se investigó el handshake del túnel.

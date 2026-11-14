# Hex Custom 10.6.4 — SP-DECODE

**App:** Hex Custom 10.6.4, versionCode 104, package `com.hex.custom.jotchuast`
(minSdk 24). APK proporcionado por Pedro (no descargado de espejos):
`Hex_Custom_10.6.4_104.apk`, 102.363.606 B,
SHA-256 `d00d6871a8f5de8d06a6513ae140d8e3344a40467712939c1dccb0659873d456`.

## Resultado

**Archivo `.hexcm` real ABRE completo.** El contenedor HXS3 es nuevo en
10.6.4 y su método se resolvió por emulación JNI de la librería nativa
`libhexvpn.so` (funciones `nativeOpen`/`nativeSeal`) con Unicorn, más
verificación en Python puro de cada capa.

El archivo de Pedro `NONE_BREAKER__0_0osx.hexcm` (7.054 B,
SHA-256 `7babe831f18dbd9822eca9fbf50ee51cd361a71310776ef0197bf3d9d97aca32`)
abre con la contraseña `None_breaker`:

| Campo | Valor |
|---|---|
| Perfil | NONE_BREAKER📡 |
| Usuario / contraseña | Nonbreaker / 224012 |
| slipstream_domain | dsl.depwise.store |
| slipstream_resolvers | 197.156.74.223:53 |
| Empresa / país | Ethio telecom / et |
| Bloqueado | true (blockRoot, blockCompany) |
| Expira | 1794700800000 ms |
| Firma | presente (64 hex) |

## Método (contenedor HXS3)

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

Derivación de claves (contraseña en UTF-8):

```
argon2_key = Argon2id(password, salt, t=3, m=65536 KiB, p=1, version=0x13, 32 B)
CONSTANTS32 = 265943050e89ae3aa403ae988c62026ef378c66a9c69be529929d7d5d3d47f3d
              (constante fija de la app, libhexvpn.so .data.rel.ro)
H1      = HMAC-SHA256(key=salt, msg=CONSTANTS32 || argon2_key)
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
El sellado (`--seal`) usa la misma construcción con salt/nonces aleatorios.

## Catálogo / nube / texto

- **No hay catálogo HTTP de proveedor.** La nube es Firebase Firestore
  (`com.hexapplications.hexvpn.cloud.FileRepository`: `reservarId`,
  `obtenerArchivo`, `subirArchivo`, `generarId`); los archivos se comparten
  por un ID `hexcustom` + 10 letras. No hay endpoint público que descargar.
  `Hex_Custom.py --url` responde `NO_CATALOG` con esta explicación.
- **No hay esquema URI propio de texto.** El manifest solo declara el filtro
  VIEW de `.*\.hex` y `application/octet-stream`. No existe `hexcustom://`.

## Archivos

| Archivo | Descripción |
|---|---|
| `Hex_Custom.py` | Decodificador principal: `decode()` + `run()` + CLI `--url/--file/--stdin/--self-test/--seal`. |
| `Hex_Custom_archivos.py` | Decodificador de archivos `.hexcm` (abrir y sellar). |
| `Hex_Custom.png` | Icono 512×512 (adaptativo: fondo `#121212` + foreground `res/sK.webp`). |
| `README.md` | Este archivo. |

Ambos scripts son Python 3.10+ solo-stdlib (Argon2id, AES-256-GCM y
XChaCha20-Poly1305 en Python puro, verificados contra argon2-cffi /
PyCryptodome y contra la librería nativa emulada). Con argon2-cffi +
PyCryptodome el descifrado tarda ~0,3 s; en stdlib puro el Argon2id
(m=65536 KiB) tarda varios minutos.

## Uso

```bash
python3 Hex_Custom.py archivo.hexcm --password <pass> [--summary] [-o salida.json]
python3 Hex_Custom.py --self-test
python3 Hex_Custom_archivos.py --seal perfil.json --password <pass> -o out.hexcm
python3 Hex_Custom.py --url   # -> NO_CATALOG (no hay catalogo HTTP)
```

## Verificación

- `--self-test`: 7/7 (vector RFC 9106 Argon2id, vector NIST AES-256-GCM,
  vector de respuesta conocida XChaCha20-Poly1305, round-trip sellar→abrir,
  tag GCM alterado rechazado, tag Poly1305 alterado rechazado, flags sin
  contraseña rechazados).
- Archivo real de Pedro abre (tags GCM y Poly1305 auténticos, JSON válido).
- Round-trip con el perfil real: sellar → abrir idéntico, firma conservada.
- Contraseña incorrecta → `WRONG_PASSWORD`.

## Cobertura previa del repo (verificada en este APK)

- El repo cubre **Hex Custom 10.6.1 (build 101)** solo como análisis
  (`decoders/Python/apps/Hex_Custom/`: ANALYSIS.md, README.md, TESTING.md,
  sin decodificador funcional; estado `pending_protected_file_method`) y
  **Hex Tunnel 1.7.3 (build 73)** con decodificador funcional de otro
  formato (Base64 + PBKDF2 + AES-GCM + ChaCha20-Poly1305 doble). **Ninguno
  de los dos abre el HXS3 de 10.6.4**: todo cambió (los 5 DEX, libkovsec.so
  y kov-sec.dat; el contenedor pasó a ser binario HXS3 v3 con KDF Argon2id
  en libhexvpn.so, una librería Rust nueva). Este trabajo actualiza la
  cobertura a 10.6.4.

## Pendientes

1. **Fórmula de la firma** (`signature`, SHA-256 de 64 hex): no se pudo
   determinar con la única muestra disponible (se probaron SHA-256/HMAC del
   JSON sin signature, con la contraseña y con las claves de sesión). No
   hace falta para abrir el archivo. Al sellar se pone
   `SHA-256(JSON sin signature)` y se advierte; la app podría rechazar el
   archivo al importarlo si valida la firma.
2. **Rama sin contraseña** (flags bit 0 = 0): la app usa otra derivación
   (constantes `.data.rel.ro` + MIX, sin Argon2id). No existe ninguna
   muestra `.hexcm` sin contraseña para verificarla; el script devuelve
   `UNSUPPORTED_FLAGS` en ese caso.
3. Confirmación de extremo a extremo con un segundo `.hexcm` (sin
   contraseña, o sellado por la app en un teléfono).

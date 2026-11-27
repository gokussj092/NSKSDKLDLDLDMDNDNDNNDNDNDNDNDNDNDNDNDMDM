# ANALYSIS — NadiaVPN 1.4.6 (`com.danaelh4.nadvpn`, code 45)

- **App:** NadiaVPN 1.4.6 (versionCode 45)
- **APK analizado:** `~/workspace/user/files/base__5__0_tvtg.apk`
  (42,547,658 bytes, SHA-256
  `d91baaa578d14190ee2b57134ce90defbc28967c8f380dc479122d53e3ac93d2`)
- **Muestra:** texto `nad://sec2:` real aportado por Pedro (el enlace
  completo no se almacena en el repo; ver REPRODUCE.md)
- **Fecha:** 2026-11-26/27
- **Alcance:** integración FILE_ONLY (archivos `.nad` + textos
  `nad://`). Sin catálogo, sin push, sin despliegue desde este trabajo.
- **Veredicto: EL TEXTO ABRE.** HMAC verificado, JSON completo, ningún
  campo queda cifrado. El decoder de archivos es VERIFIED_SYNTHETIC
  (ida y vuelta con sobre re-cifrado, 3/3: V2, PW2 con contraseña,
  binario).

> NadiaVPN **NO** es de la familia del lote 13 (Fat/VLX/IRFAN/Katiba/
> Tx/Mehaf). No hay Argon2id ni AES-GCM ni `strongteam.co`. El sobre
> `sec2` es propio: **PBKDF2-HMAC-SHA256 + AES-256-CBC + HMAC-SHA256**,
> con la clave ligada a la firma del APK y a un secreto nativo
> (`libandroidx.graphics.path.so`).

## 1. Layout del sobre

`nad://sec2:` + Base64 → 1120 bytes en la muestra real, sin magic.

| Campo | Bytes |
|---|---|
| `salt` | `[0:16]` |
| `iv` | `[16:32]` |
| `tag` (HMAC-SHA256) | `[32:64]` |
| `ciphertext` (AES-256-CBC) | `[64:]` |

Mínimo 80 bytes. El cifrado/descifrado es `Lv/b.j` (cifrar) /
`Lv/b.f` (descifrar); la importación es `Lo/f.b` (`nad://sec2:` →
substring(11) → Base64 → `Lv/b.f` → `Lo/f.f` parsea el JSON). Con
contraseña es `nad://pw2:` (`Lv/b.i` / `Lv/b.e`, mismo sobre, 25000
iteraciones). Las variantes legacy `sec:`/`pw:` (V1) no se analizaron.

## 2. KDF y parámetros (verificado contra el DEX y el .so nativo)

```
K1 = secreto maestro (32 B, nativo, ver §3)
K2 = SHA-256 del certificado de firma del APK (32 B, ver §3)
info      = K1 || K2                                   (64 B)
salt_mac  = HMAC-SHA256(clave=K2, datos=salt)
derivada  = PBKDF2-HMAC-SHA256(password=info, salt=salt_mac,
                               iteraciones=20000, dkLen=64)
key       = derivada[0:32]        (AES-256)
macKey    = derivada[32:64]
tag       = HMAC-SHA256(macKey, salt || iv || ciphertext)
plaintext = AES-256-CBC-decrypt(key, iv, ciphertext), unpad PKCS7
```

Con contraseña (`pw2:`): `info = K1 || K2 || password.trim()` UTF-8,
25000 iteraciones. Error si el HMAC no coincide: `"Error de
integridad: Firma de archivo no coincide"`.

### De dónde salen K1 y K2 (nativo, `libandroidx.graphics.path.so`)

- **K2** = salida de `getAppSignatureSha256` (0x343c): SHA-256 del
  certificado que firmó el APK instalado, comparado con el hash
  esperado incrustado en el .so. Si el PM falla o el hash no
  coincide, la salida es el hash del bloque de firma v2/v3 del
  archivo APK o ceros, y se marca con flags.
- **K1** = salida de `getSecurityMasterSecret` (0x35a4): mezcla
  determinista (función 0x8e0c) de tres entradas de 32 B: una tabla
  fija del .so, un keystream PRNG (semilla `0x9e3779b9`) y la salida
  de `getAppSignatureSha256`, XOR con una mezcla pura de 64 rondas
  (función 0x9048). Si los flags de integridad son distintos de cero,
  el resultado se altera con un XOR-mangle por byte (semilla derivada
  de los flags).
- Las tres piezas (mezcla 0x9048, mezcla 0x8e0c y XOR-mangle) se
  verificaron **byte a byte contra el código real ejecutado en
  Unicorn**. Las constantes de trabajo viven solo en
  `tools/file_decoder.py` (y en los scripts de investigación
  `tools/nadiavpn-text.py` / `tools/nadiavpn-file.py`); no se
  duplican en este documento.
- **Flags** `w19 = flags(0x6624) | flags(0x432c)`. En un dispositivo
  limpio `w19 = 1`. La muestra real abrió con `w19=2`; el decoder
  prueba la lista completa de `w19` plausibles hasta que el HMAC
  verifica, así que abre enlaces exportados en otros estados del
  dispositivo con el mismo build. Enlaces de un build re-firmado con
  otro certificado **no** abrirán con estas constantes (K2 y K1
  cambian).

### Auditoría HMAC (política de evidencias §2.2)

- Integridad del sobre: HMAC-SHA256 sobre `salt || iv ||
  ciphertext`, comparado en tiempo constante; verificado en la
  muestra real (el HMAC verifica y el JSON abre completo).
- Integridad del transporte: no aplicable — los enlaces/archivos los
  aporta el usuario; el decoder no descarga nada.
- Autenticación de conexión VPN: NO observada — el decoder no
  establece ninguna conexión ni prueba ningún login. La presencia del
  HMAC no demuestra autenticación de conexión.

## 3. Contenido descifrado (muestra real)

JSON de 1046 bytes, 24 claves. **Ningún valor queda cifrado.** Es un
**perfil de prueba** (SSH+SSL sobre el puerto 443 con proxy, SNI y
payload WebSocket; `isProtected`/`isLocked`/`blockRoot` en true,
`nadiaSig` = `NADIA_SEC_OK`, `hasPassword` = false). Los valores
concretos (hosts, usuarios, contraseñas) no se reproducen en este
expediente: son datos de un perfil de prueba aportado por Pedro y no
aportan nada al método. La forma (claves y tipos) se verifica en
`tests/test_nadia_vpn.py::test_real_sample_opens` sin almacenar el
enlace.

## 4. Archivos .nad

- Import por intent VIEW (`file`/`content`, `.*.nad` y `.*.sks`).
- Contenido: texto con prefijo `NADIA_SEC_V2:` / `NADIA_SEC_PW2:` /
  `NADIA_SEC_HWID:` / `NADIA_SEC_HWID_PW:` + Base64 del sobre (§1)
  (o sobre binario directo). En claro: `java.util.Properties` XML
  ("NadiaVPN Hardened Profile V2").
- `tools/file_decoder.py` decodifica V2/PW2 y sobre binario directo;
  verificado por ida y vuelta (3/3: V2, PW2 con contraseña, binario).
  HWID: detecta el prefijo y responde `HWID_REQUIRED` /
  `HWID_PASSWORD_REQUIRED` (flujo estándar del repo); con HWID
  suministrado responde `UNSUPPORTED_VARIANT` — la derivación de los
  slots `NHW1` no está verificada (sin muestra real).
- `.sks`: aceptado en el mismo intent-filter, pero su ruta de parseo
  NO se localizó en el DEX. Sin decoder (regla: no se incluyen .sks).

## 5. Catálogo en vivo — EXCLUIDO de esta integración

El catálogo en vivo existe y se descifró al 100 % durante el análisis
(1 servidor gratuito, 0 redes, 0 payloads), pero queda **FUERA de
esta integración por decisión explícita del propietario
(2026-11-26)**. Ningún dato del catálogo — ni URL, ni host/IP, ni
usuario/contraseña SSH, ni session id, ni token — aparece en este
expediente, en el decoder ni en ningún archivo del staging. El
catálogo completo solo existe como adjunto de chat. El script
`nadiavpn-catalog.py` NO se incluye aquí (prohibido por el encargo).

## 6. Qué quedó sin verificar (PENDING)

1. Archivo `.nad` real exportado por la app (el decoder se verificó
   por ida y vuelta con sobre re-cifrado, no con un archivo real).
2. Muestra real `nad://pw2:` con contraseña.
3. Archivo `.nad` con bloqueo HWID (slots `NHW1`) y su HWID.
4. Conexión SSH real al servidor del perfil o del catálogo.
5. Variantes legacy V1 (`nad://sec:` / `nad://pw:`,
   `NADIA_SEC_V1:`).

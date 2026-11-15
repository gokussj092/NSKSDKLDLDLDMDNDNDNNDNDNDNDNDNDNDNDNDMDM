# V2Box - V2ray Client 6.2.3 (build 88) — SP-DECODE

**Paquete:** `dev.hexasoftware.v2box` · **Versión:** 6.2.3, build 88, minSdk 29
· **XAPK APKPure:** 34.268.666 B, SHA-256
`18e5181dd51cf1ddccbda6f334f9437005403c9f7258ee3823b7838869728fe1`

## Lo importante: no hay catálogo del vendedor

V2Box es un **cliente V2Ray genérico**: el usuario añade sus propias URLs
de suscripción y la app las descarga y convierte en perfiles. El único
endpoint del vendedor es `https://services.hexasoftware.dev/app-settings`,
que **solo devuelve promociones** (verificado en vivo 2026-11-14: HTTP 200,
932 B, 2 promociones iOS + 1 Android, `updated_at 2026-10-31T23:22:32+00:00`).
**0 servidores, 0 payloads.** No existe ninguna URL de catálogo en el DEX.
El entregable honesto es, por tanto, un descargador de suscripciones +
decodificadores de enlaces y archivos, igual que SNI Tunnel (tanda 5).

## Qué cambió respecto al repo (6.1.2)

El repo solo cubría V2Box en `decoders/Python/v2box.py`
(`v2box://locked=` → Base64 → query params, incompleto) y
`decoders/Python/v2box_export.py` (solo formato v1, con PyCryptodome).

- **Formato v1 (.v2box, version=1): SIN CAMBIOS.** AES-256-GCM con la
  clave fija `V2BoxEncryptionKey2026_Secret!#%` (XOR 90 de 32 bytes
  guardados) o `SHA-256(password)` si está protegido. Texto plano =
  JSON con `configs` (renombrado a `a`) y `raws` (renombrado a `b`).
- **Formato v2 (.v2box, version=2): NUEVO en 6.2.3.** Sobre
  `{magic, version: 2, header, nonce, ciphertext, tag}`. El header trae
  `kdf`, `salt`, `iterations`, `expiresAt`, `deviceIds`, `recipients`.
  El payload es AES-256-GCM con clave de archivo aleatoria de 32 B y
  **AAD = bytes exactos del header JSON**. Clave de archivo según `kdf`:
  - `pbkdf2-sha256`: PBKDF2-HMAC-SHA256 (contraseña NFC, salt 16 B,
    600.000 iteraciones por defecto, 32 B).
  - `ecdh-p256`: cada recipient `{kid, epk, key}`; `kid` =
    Base64(SHA-256(clave pública P-256 del destinatario)[0:8]);
    `kek` = HKDF-SHA256(salt = `epk || pub`, ikm = shared ECDH,
    info = `v2box/2 recipient`, 44 B); la clave de archivo se descifra
    con AES-256-GCM(`kek[0:32]`, nonce `kek[32:44]`). Sin la clave
    privada P-256 del dispositivo **no se abre offline** (está en su
    Android Keystore, alias `v2box_device_p256`, no exportable).
  - `none`: la clave de archivo es la clave fija v1.
- **Enlaces `v2box://locked=` SIN CAMBIOS:** Base64 del texto de
  perfiles (uno por línea). También se registran `v2box://install-config`
  y `v2box://install-sub`, y los archivos `.v2box`.
- **Esquemas que parsea:** `vmess://`, `vless://`, `trojan://`, `ss://`,
  `socks://`, `hysteria2://`, `hy2://`. Sin Clash/YAML.
- **Suscripción:** GET a la URL que pone el usuario, cabecera
  `Connection: close`, UA `okhttp/5.3.2` (por defecto de OkHttp),
  timeout 15 s, sigue redirecciones. Lee la cabecera
  `subscription-userinfo` (upload/download/total/expire).

## Archivos

| Archivo | Descripción |
|---|---|
| `V2Box.py` | Descargador de suscripciones + decodificador de enlaces. `decode()` + `run()` + CLI `--url/--text/--self-test`. Stdlib puro. |
| `V2Box_archivos.py` | Decodificador de archivos `.v2box` v1 y v2. `decode_file()` + CLI `--file/--password/--device-key/--self-test`. Stdlib puro (AES-256-GCM, ECDH P-256 y HKDF implementados en el archivo). |
| `V2Box.png` | Icono 512×512 RGBA (copia de `apk/icon.png`). |
| `README.md` | Este archivo. |

## Uso

```bash
# Suscripción (la URL la pone el usuario; app-settings solo tiene promociones)
python3 V2Box.py --url https://services.hexasoftware.dev/app-settings
python3 V2Box.py --url <url-de-suscripcion> --json

# Decodificar enlaces en texto
python3 V2Box.py --text 'vmess://...'

# Archivo .v2box v1 sin contraseña / con contraseña
python3 V2Box_archivos.py --file export.v2box
python3 V2Box_archivos.py --file export.v2box --password Secreto123

# Archivo .v2box v2 cifrado para un dispositivo (clave privada P-256
# del destinatario: escalar de 32 B en Base64/hex, o PKCS#8 DER en
# Base64 / archivo .pem/.der)
python3 V2Box_archivos.py --file export.v2box --device-key <base64>

# Pruebas
python3 V2Box.py --self-test            # 8/8 (incluye app-settings en vivo)
python3 V2Box_archivos.py --self-test   # 7/7 (v1 y v2, ida y vuelta)
```

## Verificación

- `py_compile` OK en ambos scripts (Python 3.10+, stdlib puro).
- `V2Box.py --self-test`: 8/8 OK — parseo de los 6 esquemas de enlace,
  suscripción en Base64 entera, `v2box://locked=`, config V2Ray JSON,
  `app-settings` en vivo (3 promociones, 0 servidores),
  `subscription-userinfo`.
- `V2Box_archivos.py --self-test`: 7/7 OK — v1 sin/con contraseña (y
  contraseña incorrecta → `TAG_MISMATCH`), v2 `pbkdf2-sha256`, v2
  `none`, v2 `ecdh-p256` (sin clave → `RECIPIENT_KEY_REQUIRED`; con la
  clave correcta abre; con otra clave no coincide el `kid`), magic
  inválido. El GCM se verificó además contra `cryptography` AESGCM.
- `--url https://services.hexasoftware.dev/app-settings` en vivo:
  3 promociones, 0 servidores, `updated_at 2026-10-31T23:22:32+00:00`.

## Pendiente

Un `.v2box` real exportado (v1 o v2) y un enlace `v2box://locked=` real
cerrarían la verificación extremo a extremo (hoy solo round-trip contra
la spec recuperada del APK). Un archivo v2 `ecdh-p256` real necesita
además la clave privada P-256 del dispositivo destinatario.

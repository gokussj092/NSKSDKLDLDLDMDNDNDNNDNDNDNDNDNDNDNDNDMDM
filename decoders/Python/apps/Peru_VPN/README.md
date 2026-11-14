# Peru VPN (`com.peru.vpn`, 4.1.0 / build 410)

Proveedor nuevo para SP-DECODE. Sin cobertura previa en el repo (el
único parecido, `VPN_PLUS_PERU/`, es otra app: `com.akunt.vpn` 1.0).
Build TunnelDoom/SocketClay (`com.tunneldoom.http`,
`com.tunneldoom.sshservice`); las librerías nativas viven todas en el
split `config.arm64_v8a.apk` (libgojni.so es el núcleo v2ray en Go;
libfarikudp.so, libdns.so, libtun2socks.so, libv2ray.so, libcrypto.so,
libconscrypt_jni.so, libpdnsd.so).

## Catálogo — `Peru_VPN.py`

Petición exacta de la app (`ConfigUpdateco`, `HttpURLConnection`):
```
GET https://web.tunneldoom.space/config.json
User-Agent: Dalvik/2.1.0 (Linux; U; Android 14)
```
Sin parámetros ni auth. El endpoint responde HTTP 403 a un
User-Agent genérico de Python-urllib, así que el User-Agent Dalvik
forma parte de la petición exacta (cualquier UA de navegador también
pasa; la de urllib no).

Formato (dos capas):
1. El cuerpo es una línea Base64 → Base64 → XOR con
   SHA-256(b"test_key") cíclico (el `StringCrypter` de la app, clave
   literal "test_key") → se descartan los primeros 32 caracteres (la
   sal de 16 bytes, en hex) → JSON con `Version`, `ReleaseNotes`,
   `Servers[]`.
2. Cada campo Base64 de cada servidor se descifra con el `NoobCrypt`
   de la app: AES/CBC/PKCS7Padding, clave = SHA-256 de la clave
   `NoobPass` (bytes `star()` con XOR cíclico "QXWR" y reverso),
   IV = 16 bytes cero. Los valores Base64 de la app pueden traer
   saltos de línea en medio (Base64 de Android los ignora); el script
   quita todo el whitespace antes de decodificar. Los campos de texto
   plano (`Name`, `FLAG`, `ServerPort`, `isSSL`, ...) quedan como
   están. Los campos vacíos cifran como `h+Jn1NfeOYo/eB5LZurR8g==`
   y descifran a `""`.

Prueba real en vivo (2026-11-13, con el propio script `--url`):
**Version 509, 382 servidores, 235 con Payload, 109 SSL, 51 V2Ray,
2 SlowDNS**. El catálogo no trae array `Payloads` (aunque
`ConfigUtil` lo lee) y no tiene categoría premium/gratis: todos los
servidores listados son gratis (los dos nombres con "vip" dicen
"free vip"). La salida completa del script es idéntica al
descifrado de referencia con PyCryptodome. Un `--url` tarda ~30 s
(AES en stdlib puro sobre 382 servidores).

## Archivos — `Peru_VPN_archivos.py`

La app guarda su lista de servidores en un archivo `Zs.png` (en
filesDir) o en el recurso incrustado `noobdev.txt`: el contenido es
el mismo cuerpo StringCrypter del catálogo (una línea Base64). El
script lo descifra a JSON con los campos NoobCrypt ya abiertos.
También acepta un cuerpo de config descargado (mismo formato).

Verificación: `--self-test` 5/5 (round-trip sintético, incl. Unicode,
CRLF y V2Ray); el `noobdev.txt` incrustado en el APK abre con el
script (Version 2, 8 servidores, campos descifrados); el cuerpo en
vivo descargado abre igual que con el script de catálogo.

## Textos

Sin esquema URI propio: el manifest solo tiene MAIN/LAUNCHER, sin
intent-filter VIEW ni `scheme`. En el DEX solo aparecen los esquemas
estándar que SP-DECODE ya cubre (vmess://, vless://, trojan://,
ss://, socks://, wireguard://, hysteria2://, tuic://). No hay script
de textos.

## Uso

```bash
python Peru_VPN.py --url                  # descarga y descifra el catálogo remoto
python Peru_VPN.py respuesta_guardada     # mismo, desde un archivo local
python Peru_VPN_archivos.py Zs.png        # archivo de config de la app
python Peru_VPN_archivos.py noobdev.txt   # recurso incrustado
python Peru_VPN_archivos.py --self-test   # round-trip sintético
```

Solo biblioteca estándar de Python 3.10+ (AES implementado en el
propio script, verificado contra PyCryptodome).

## Pendientes

- Confirmación extremo a extremo con un `Zs.png` real sacado del
  teléfono (el formato ya está probado contra el recurso incrustado
  y contra el cuerpo en vivo, así que el riesgo residual es bajo).
- Sin resolver: los archivos incrustados `assets/flags/zs.png` y
  `assets/config/.../config.json` (JSON con `EncServer` + `Nonce` +
  `Hash`) usan otro esquema que no abrió con NoobCrypt, AESCrypt/
  GRETTA, StringCrypter, AES-CBC/CTR/GCM con esas claves. No es el
  catálogo en vivo ni el formato de `Zs.png`, así que no bloquea
  nada; queda anotado en `NOTES.md`.
- La app no usa archivos `.sks`.

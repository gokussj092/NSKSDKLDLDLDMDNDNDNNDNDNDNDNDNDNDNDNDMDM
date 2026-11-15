# Marvs SSH (T20-VPN) v1.10.5.3

Package `vpn.marvs.ssh`, versionCode 47, versionName v1.10.5.3. En
Google Play y APKPure figura como "T20-VPN" (desarrollador sando--k).
App basada en v2rayNG + núcleo Sandok/Ultra (AndroidLibXrayLite v2.5,
Go 1.24.3), con cadenas ofuscadas con LSParanoid
(`Deobfuscator$T20VPN$app`, 20 chunks, 8,040 call sites; resueltas con
el port verificado de RNV). Familia StrongTeam/Marvs (hermana de
co.strongteam.marvsudp / MM Tunnel y co.strongteam.jetroi).

## Archivos

| Archivo | Descripción |
|---|---|
| `Marvs_SSH.py` | Catálogo: descarga (POST) + descifrado Argon2id/AES-256-GCM. `decode()` + `run()` + CLI `--url`. |
| `Marvs_SSH_archivos.py` | Decodificador de archivos de perfil `.t20` (mismo sobre, claves K1/K2). |
| `Marvs_SSH.png` | Icono compuesto del APK (foreground xxxhdpi 432×432 sobre blanco), 512×512. El `icon.png` del XAPK es de 0 bytes. |
| `configfile.json` | Asset incluido del APK (`assets/configfile.json`): catálogo de ejemplo cifrado con K2. Sirve para `--self-test`. |
| `catalog_sample.b64` | Cuerpo en vivo descargado el 2026-11-14 (416,145 bytes, SHA-256 `49088c1b…`): NO abre con K1 ni K2 — muestra del fallo honesto. |

Dependencias: Python 3.10+, solo biblioteca estándar. Argon2id (RFC 9106)
y AES-256-GCM están implementados en Python puro en los scripts
(verificados contra argon2-cffi y PyCryptodome). Un descifrado tarda
~15-20 s; el catálogo en vivo que no verifica puede tardar ~1 min
porque prueba ambas claves.

## Catálogo

Método recuperado del núcleo Go (`libgojni.so`,
`github.com/2dust/AndroidLibXrayLite.CU`). La app NO hace GET: hace un
POST con un campo de formulario.

```
POST https://strongteam.co/api/t20/
Content-Type: application/x-www-form-urlencoded
User-Agent: Go-http-client/1.1
Body: hash=xsandokUpdatex
```

Sin auth, sin cookies, sin más cabeceras. El servidor responde HTTP 200,
`Content-Type: text/plain; charset=utf-8`, cuerpo de una sola línea
Base64 (416,145 bytes el 2026-11-14, determinista entre peticiones).
El cuerpo es un sobre Argon2id + AES-256-GCM (el mismo que produce
`Encrypt()`):

```
Base64( salt[16] || nonce[12] || AES-256-GCM(key, nonce, AAD=salt) )
key = Argon2id(password, salt, time=3, memory=8192 KiB, threads=1, 32 B)
```

Dos contraseñas de 32 bytes en `libgojni.so` `.rodata` (constantes de
formato, no credenciales de cuenta):

- **K1** `/PiXB5X3ZU8j7vZaZOiCqgo2r4l74c27` — `decrypt()`/`Encrypt()`,
  la ruta del catálogo en vivo (CU llama a `decrypt` sobre la respuesta).
  Offset `.rodata` 0x365e07 (verificado por desensamblado de `decrypt()`).
- **K2** `WoxBk8Vf9VJMiJ1sOTnntC91n6H+kZjC` — `DO()`/`do_()`, el asset
  incluido y las cadenas de archivos `.t20`. Offset `.rodata` 0x365e27
  (verificado por desensamblado de `DO()`).

El JSON descifrado usa el esquema Sandok/Ultra (`Version`,
`ReleaseNotes`, `Telegram`, `WhatsApp`, `Facebook`, `DefOVPNUser`,
`DefOVPNPass`, `HysteriaUser`, `HysteriaOBFS`, `DefaultOVPNCert`,
`isTimerOn`, `timetoadd`, `Servers[]`, `Networks[]`), NO el esquema
XXTEA `Free_servers`/`Payloads` de los demás proveedores.

### Prueba real en vivo (2026-11-14)

- El endpoint responde HTTP 200 y el script descarga el cuerpo completo
  (416,145 bytes, SHA-256 `49088c1b7962dcc5e28ae7a67845a22f38209f4bd92dfe3c5b47bc515e0973cf`,
  idéntico en 10 de 10 peticiones).
- **El cuerpo en vivo NO verifica con K1 ni con K2.** Se probaron
  Argon2i, Argon2id con memoria 16384 KiB, y las claves K1/K2 de
  RNV/ATNET: ninguno abre el tag GCM. El servidor parece haber rotado
  la clave del catálogo en vivo después de esta versión del APK, igual
  que RNV Tunnel VPN y AT NET VPN (misma familia StrongTeam, mismo
  síntoma). El script lo reporta como `LIVE_DECRYPT_FAILED` en vez de
  afirmar un descifrado falso.
- El asset incluido **sí abre con K2** (verificado: tag GCM auténtico,
  JSON válido, Version `1.01`, 1 Server, 1 Network):

```
python Marvs_SSH.py --self-test
# {"self_test": "OK", "key": "K2", "version": "1.01", "servers": 1, "networks": 1}
```

Uso:

```
python Marvs_SSH.py --url -o catalogo.json   # descarga en vivo
python Marvs_SSH.py configfile.json           # asset incluido
```

Notas de descarga: `urllib` trunca el cuerpo fragmentado en la mayoría
de las peticiones (`IncompleteRead` a ~300 KiB) y Cloudflare ignora
`Range` en este POST, así que el script reintenta el POST completo
hasta obtener el cuerpo entero (en vez de reanudar por rangos). La
descarga se hace con `http.client` y túnel CONNECT explícito cuando hay
proxy. La URL de iconos es aparte y no es el catálogo:
`https://strongteam.co/nets/<nombre del icono>` (NetworkIconCache).

## Archivos `.t20`

El manifest declara la importación `.t20` (`application/x-t20`,
`application/octet-stream`, `.*\.t20`, activity
`com.v2ray.ang.ui.ConfigFileParser`). Al importar, la app lee el
archivo como texto y prueba, en orden: `Libv2ray.parseConfig()`
(config plana) y, si falla, `Hometab.Companion.a()` =
`Libv2ray.do_()` (el Go `DO()`, clave K2); si nada abre, "Invalid JSON
or decryption error". Al EXPORTAR/compartir un perfil, la app cifra el
JSON Gson del NetworkList con `Libv2ray.encrypt()` (el Go `Encrypt()`,
clave K1) y lo guarda como `<nombre>.t20` (NetworkAdapter). Este
script prueba AMBAS claves (K1 primero, luego K2) y reporta cuál abrió
el sobre. El texto descifrado es el JSON del perfil (Name, TunnelType,
Payload, SNI, V2rayConfig, etc.). Las protecciones (contraseña, HWID,
bloqueo de red) viven dentro del JSON y se verifican después del
descifrado.

**Verificación:** el sobre está verificado contra la propia librería
de la app — `configfile.json` abre con K2 y el round-trip
cifrar/descifrar es exacto con AMBAS claves (K1 y K2). **Falta** la
confirmación de extremo a extremo con un `.t20` real exportado por la
app en un teléfono (no existe ninguna muestra `.t20` en este análisis).
Los archivos `.sks` están excluidos por indicación de Pedro y no se
implementan (esta app tampoco los usa).

```
python Marvs_SSH_archivos.py perfil.t20 -o perfil.json
python Marvs_SSH_archivos.py --self-test
```

## Textos/enlaces

**Sin esquema funcional propio de Marvs SSH.** Los esquemas del
manifest son los genéricos de v2rayNG (`v2rayng://install-config`,
`v2rayng://install-sub`). Los únicos prefijos `://` en la app son los
enlaces estándar de protocolos que SP-DECODE ya cubre (`vmess://`,
`vless://`, `trojan://`, `ss://`, `socks://`, `wireguard://`,
`hysteria2://`, `tuic://`, `hy2://`, `http://`); no hay un esquema
propio cifrado tipo `darktunnel://` que decodificar.

## Cobertura del repo

No existe proveedor Marvs SSH / T20-VPN en el repo SP-DECODE (rama
`feat/nuevas-integraciones`, revisado 2026-11-14). La app hermana
MM Tunnel (`co.strongteam.marvsudp`) sí está cubierta
(`apps/MM_Tunnel`) con la misma familia de endpoint
(POST `https://strongteam.co/api/mmtunnel/`, mismo valor de hash) pero
sus propias claves; nada se reutilizó de ella sin verificarlo en ESTE
APK (`libgojni.so` y `assets/configfile.json` de vpn.marvs.ssh):
Marvs usa memoria Argon2 8192 KiB (verificado por desensamblado + tag
GCM del asset) y claves distintas.

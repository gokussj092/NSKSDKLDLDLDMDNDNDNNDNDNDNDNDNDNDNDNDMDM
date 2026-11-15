# MM Tunnel (Marvs UDP) v1.11.06.1

Package `co.strongteam.marvsudp`, versionCode 48, versionName v1.11.06.1.
En Google Play y APKPure figura como "MM Tunnel" (desarrollador sando--k).
App basada en v2rayNG + núcleo Sandok/Ultra (AndroidLibXrayLite, Go), con
cadenas ofuscadas con LSParanoid (`Deobfuscator$MMTunnel$app`). Familia
StrongTeam/Marvs (hermana de Marvs SSH / T20-VPN `vpn.marvs.ssh` y de
JetRoi `co.strongteam.jetroi`).

## Archivos

| Archivo | Descripción |
|---|---|
| `Marvs_UDP.py` | Catálogo: descarga (POST) + descifrado Argon2id/AES-256-GCM. `decode()` + `run()` + CLI `--url` / `--fields` / `--self-test`. |
| `Marvs_UDP_archivos.py` | Decodificador de archivos de perfil `.mmt` (mismo sobre, claves FILE/FIELD + letra marcadora). |
| `Marvs_UDP.png` | Icono del APK (`icon.png` del XAPK), 512×512. |
| `configfile.json` | Asset incluido del APK (`assets/configfile.json`): catálogo de ejemplo cifrado con FIELD_SECRET. Sirve para `--self-test`. |

Dependencias: Python 3.10+, solo biblioteca estándar para el sobre del
catálogo. Argon2id (RFC 9106) y AES-256-GCM están implementados en
Python puro en los scripts (verificados contra argon2-cffi y
PyCryptodome: la clave Argon2id a m=16384 es byte-idéntica). Un
descifrado del sobre tarda ~45-90 s en stdlib puro; ~0,3 s con
argon2-cffi + PyCryptodome, que además son obligatorios para
decodificar los campos protegidos (`--fields`).

## Catálogo

Método recuperado del núcleo Go (`libgojni.so`,
`github.com/2dust/AndroidLibXrayLite.CU`). La app NO hace GET: hace un
POST con un campo de formulario.

```
POST https://strongteam.co/api/mmtunnel/
Content-Type: application/x-www-form-urlencoded
User-Agent: Go-http-client/1.1
Body: hash=xsandokUpdatex
```

Sin auth, sin cookies, sin más cabeceras. El servidor responde HTTP 200,
`Content-Type: text/plain; charset=utf-8`, cuerpo de una sola línea
Base64 (1,154,861 bytes el 2026-11-14, SHA-256
`e94bb7420c32325844079a9528266e285db0f9e095c3768ef091c39834e26773`).
El cuerpo es un sobre Argon2id + AES-256-GCM (el mismo que produce
`Encrypt()`), con una letra ASCII aleatoria insertada en el índice 3
del Base64 DESPUÉS de codificar (por eso el cuerpo mide 1 mod 4):

```
Base64( salt[16] || nonce[12] || AES-256-GCM(key, nonce, AAD=salt) )
key = Argon2id(password, salt, time=3, memory=16384 KiB, threads=1, 32 B)
```

Dos contraseñas de formato en `libgojni.so` `.rodata` (constantes de
formato, no credenciales de cuenta), recuperadas por desensamblado de
ESTE APK y verificadas abriendo los sobres reales:

- **FILE_SECRET** `iOi/hqT/TocUv0UbDImfWPGR1mfSdzzX` — `Encrypt()`/
  `decrypt()`, la ruta del catálogo en vivo (CU llama a `decrypt`
  sobre la respuesta) y los archivos `.mmt` exportados. Offset
  `.rodata` 0x365e74 (dos cargas de 16 bytes en `Encrypt` 0x1012110 y
  `decrypt` 0x10124c0).
- **FIELD_SECRET** `NewDecryptLibPassword` — `EO()`/`DO()`, el asset
  incluido y cada campo protegido dentro del catálogo. Se construye en
  `EO` 0x10129d0 / `DO` 0x1012df0 a partir de `.rodata` 0x353439
  (`NewDecryptLibPass`, 16 B) + `Password` (inmediato movk), longitud
  0x15 = 21 bytes.

El script prueba en orden: sobre FILE sin la marcadora, sobre FIELD
tal cual y sobre FILE tal cual, y reporta cuál abrió el sobre.

El JSON descifrado usa el esquema Sandok/Ultra (`Version`,
`ReleaseNotes`, `Telegram`, `WhatsApp`, `Facebook`, `DefOVPNUser`,
`DefOVPNPass`, `HysteriaUser`, `HysteriaOBFS`, `DefaultOVPNCert`,
`isTimerOn`, `timetoadd`, `Servers[]`, `Networks[]`), NO el esquema
XXTEA `Free_servers`/`Payloads` de los demás proveedores. **No existe
ningún marcador gratis/premium en los datos**: los 37 servidores vienen
en una sola lista.

### Prueba real en vivo (2026-11-14)

- El endpoint responde HTTP 200 y el script descarga el cuerpo completo
  (1,154,861 bytes, SHA-256 `e94bb742…6773`). El cuerpo **abre con
  FILE_SECRET** (sin la marcadora): Version `2.71`, ReleaseNotes
  `Servers FIX & FIX GCP`, **37 servidores, 818 redes**:

```
python Marvs_UDP.py --url -o catalogo.json
# {"key": "FILE", "version": "2.71", "servers": 37, "networks": 818, "fields_decoded": false, "field_envelopes": null}
```

- El asset incluido **abre con FIELD_SECRET** (tag GCM auténtico,
  JSON válido, Version `1.01`, 34 servidores, 555 redes, 3,335 sobres
  de campo únicos):

```
python Marvs_UDP.py --self-test
# {"self_test": "OK", "key": "FIELD", "version": "1.01", "servers": 34, "networks": 555}
# {"field_sample": "OK", "unique": 48, "decoded": 48, "failed": 0}
```

- Desglose del catálogo en vivo: ServerType Normal Server 24, DNS
  V2ray 5, GCP 2, XHTTP 2, Cloudfront 2, Alibaba 1, CF Worker 1;
  ServerProtocol OVPN 17, V2ray 10, V2ray,DNSTT 5, SSH,DNSTT 3, UDP
  Hysteria 2; V2rayProtocol VLESS 35, Trojan 2; isdefUser True 36,
  False 1. TunnelType: SSL Direct 262, Http/Ws Proxy 238, V2ray 143,
  Slow DNS 72, SSL + Payload + WS 69, UDP Hysteria 26, Direct UDP 5,
  Direct TCP 3. Redes con sobre Payload: 700; con sobre SNI: 541.

Uso:

```
python Marvs_UDP.py --url -o catalogo.json          # descarga en vivo (campos codificados)
python Marvs_UDP.py --url --fields --workers 2      # descarga + decodifica los campos (falla cerrado: 37 no verifican)
python Marvs_UDP.py --url --fields-partial --workers 2  # descarga + decodifica 3,427/3,464; los 37 restantes quedan codificados y se reportan
python Marvs_UDP.py configfile.json                  # asset incluido
python Marvs_UDP.py configfile.json --fields --workers 2  # asset completo: 3,335/3,335 campos, 0 fallos
python Marvs_UDP.py --self-test                      # asset + muestra de campos
```

Notas de descarga: `urllib` trunca el cuerpo fragmentado en la mayoría
de las peticiones (`IncompleteRead` a ~300 KiB) y Cloudflare ignora
`Range` en este POST, así que el script reintenta el POST completo
hasta obtener el cuerpo entero (en vez de reanudar por rangos). La
descarga se hace con `http.client` y túnel CONNECT explícito cuando hay
proxy. La URL de iconos es aparte y no es el catálogo:
`https://strongteam.co/nets/<nombre del icono>` (NetworkIconCache).

## Campos protegidos (`--fields`)

Cada campo protegido (arriba: `DefOVPNUser`, `DefOVPNPass`,
`HysteriaUser`, `HysteriaOBFS`, `DefaultOVPNCert`; por servidor:
`ServerIPHost`, `OVPNUser`, `OVPNPass`, `UDP_obfs`, `UDP_user`,
`CustomCertificate`, `SlowDNSHost`, `SlowDNSKey`, `V2rayUUID`,
`H2pass`, `TrojanPass`, `V2rayPath`; por red: `Payload`,
`CustomProxy`, `SNI`, `V2rayConfig`, `BugDNS`, `V2rayAddress`,
`V2rayHost`, `V2raySNI`) es a su vez un sobre EO (FIELD_SECRET,
Argon2id m=16384 + AES-256-GCM, AAD=salt). Solo los valores con forma
Base64 de 60 o más caracteres son sobres; los más cortos ya son texto
plano (por ejemplo, los campos de nivel superior del catálogo en vivo
ya vienen en claro, como `DefOVPNUser` = `sandoki`).

Por defecto el script NO decodifica los campos: 3,464 sobres × ~88 s
en stdlib puro no es viable. Con `--fields` se decodifican todos, lo
que requiere argon2-cffi + PyCryptodome (~0,3 s por sobre,
paralelizable con `--workers`). La decodificación falla cerrada: un
solo tag malo aborta todo el documento en vez de devolver credenciales
parciales. Verificado: muestra de 48/48 sobres del asset, 0 fallos;
asset completo: 3,335/3,335 sobres, 0 fallos; catálogo en vivo:
3,427/3,464 sobres abren y **37 no verifican** (ver abajo) — por eso
`--fields` falla cerrado sobre el catálogo en vivo y existe
`--fields-partial`: decodifica los 3,427 que abren y deja los 37
codificados tal cual, reportando cada uno por ubicación.

**Los 37 sobres que no abren (verificado 2026-11-14):** son Payload
(15), SNI (13) o CustomProxy (9) de 16 redes de Egipto (Etisalat
«اتصالات مصر» y WE «وي», p. ej. `《🦊 Egypt 🇪🇬 [½ 🍒MIX اتصالات مصر🆕]
[𝐒𝐒𝐇]》`); ninguna existe en el asset. No abren con FIELD_SECRET ni
con ninguna variante probada: FILE_SECRET,
`NewDecryptLibPasswordIICore` (la contraseña «II Core» del config
`mmtunnel` del repo, que además NO está en el `libgojni.so` de este
APK), Argon2i, memoria 4096–32768 KiB, tiempo 1–3, versión 0x10/0x13,
AAD con sal o sin AAD, AES-GCM, ChaCha20-Poly1305, tag antes del
texto cifrado, ni AES-CBC/ECB directo. Uno de ellos decodifica a solo
43 bytes, por debajo del mínimo de 44 bytes del sobre EO, así que al
menos algunos no son sobres EO en absoluto. El `libgojni.so` de este
APK no contiene ninguna otra función de descifrado de campos aparte
de EO/DO, así que nada en el APK puede abrirlos con las claves que
contiene. Quedan como pendiente: esos 16 perfiles de Egipto no se
pueden usar completos sin saber con qué se cifraron sus
Payload/SNI/CustomProxy.

## Archivos `.mmt`

El manifest declara la importación `.mmt` (`application/x-mmt`,
`application/octet-stream`, `.*\.mmt`, activity
`com.v2ray.ang.ui.ConfigFileParser`). Al importar, la app lee el
archivo como texto y llama `Libv2ray.parseConfig()` (el Go
Encrypt/decrypt); si falla, lo intenta como JSON plano
(`Hometab.Companion.a()`). Al EXPORTAR/compartir un perfil, la app
hace `Gson.toJson(NetworkList)`, lo cifra con `Libv2ray.encrypt()` (el
Go `Encrypt()`, clave FILE_SECRET), inserta una letra ASCII aleatoria
en el índice 3 del Base64 y lo guarda como `<nombre>.mmt`
(NetworkAdapter). Este script prueba en orden FILE sin marcadora, FILE
tal cual y FIELD tal cual, y reporta cuál abrió el sobre. El texto
descifrado es el JSON del perfil (Name, TunnelType, Payload, SNI,
V2rayConfig, etc.). Las protecciones (contraseña, HWID, bloqueo de red)
viven dentro del JSON y se verifican después del descifrado.

**Verificación:** el sobre está verificado contra la propia librería
de la app — `configfile.json` abre con FIELD_SECRET, el catálogo en
vivo abre con FILE_SECRET sin la marcadora, y el round-trip
cifrar/descifrar es exacto con AMBAS claves (FILE con marcadora y
FIELD sin ella). **Falta** la confirmación de extremo a extremo con
un `.mmt` real exportado por la app en un teléfono (no existe ninguna
muestra `.mmt` en este análisis). Los archivos `.sks` están excluidos
por indicación de Pedro y no se implementan (esta app tampoco los usa).

```
python Marvs_UDP_archivos.py perfil.mmt -o perfil.json
python Marvs_UDP_archivos.py --self-test
# {"self_test": "OK", "key": "FIELD", "version": "1.01", "servers": 34, "networks": 55
...[truncated 3010 chars]
# SLOW DNS 6.0.0 — catálogo

Package `slowdns.minapronetvpn.com.eg`, versionCode 6, versionName 6.0.0,
minSdk 24. APK descargado de APKPure (APKMirror no tenía listado) y
verificado contra Google Play: la versión pública en Play es 6.0.0
(actualizada 19 oct 2026; su registro de cambios indica "V6.0.0(6)").
SP-DECODE no cubría esta app (sin carpeta en `decoders/Python/apps/`).

## Método del catálogo (dos etapas)

La app descarga el catálogo en dos GET simples (OkHttp, sin cabeceras
propias ni autenticación), descifrados con la misma función `k()` de
`u9/a.java`:

**Etapa 1 — índice:**
`GET https://raw.githubusercontent.com/MinaDiNabil/update.link/refs/heads/main/slowdns_updater`
→ `k(cuerpo, "m")` → GettterConfig JSON `{ServerLink, ServerPassWD, appSecurity}`.

**Etapa 2 — catálogo:**
`server_pass = k(ServerPassWD, "m")`,
`catalog_url = k(ServerLink, server_pass)` →
`https://raw.githubusercontent.com/MinaDiNabil/update.link/refs/heads/main/slowdns_config.json`,
`GET catalog_url` → `k(cuerpo, server_pass)` → MinaConfig JSON
`{version, message, serversList[], networksList[]}`.

**La función `k(input, password)`:**
1. Quitar 6 caracteres basura: posiciones 5–7 y, del resultado,
   posiciones 20–22 (en el vivo son `L5p` las dos veces).
2. Base64-decodificar el resto.
3. Pasar el texto por `CHZCORE.p()` = el nativo `xde(str, 0)` de
   `libchzcore.so` (CHZCORE es un almacén MMKV; los nombres de los
   métodos nativos están ofuscados con el ofuscador "oz" y solo aparecen
   en `.bss` tras ejecutar los constructores de la librería — se
   recuperaron emulando `JNI_OnLoad` + constructores con Unicorn y
   leyendo la tabla `JNINativeMethod` construida en `.bss`:
   `xde` en `0xa29d8`, `xec` en `0xa24b8`). `xde` hace:
   Base64-decodificar → invertir los bytes → ROT+20 solo sobre letras
   A–Z/a–z. Su inversa es `xec`: ROT+6 → invertir → Base64-codificar.
4. `a(resultado, password)`: Base64-decodificar →
   `salt[0:16] || IV[16:32] || ct` → PBKDF2-HmacSHA1(password, salt,
   10000 iteraciones, clave 256 bits) → AES-256-CBC/PKCS7 → JSON UTF-8.

## Estado en vivo (2026-11-13, verificado con `SLOW_DNS.py --url`)

- Etapa 1: HTTP 200, 4675 B; etapa 2: HTTP 200, 177958 B.
- Catálogo: **version 4**, message vacío, **7 servidores**
  (United States, Canada, Germany, Netherland, United Kingdom,
  Singapore, Australia; todos con host
  `dnstt-servers.minapronetvpn.com`, usuario `minapronet`) y
  **54 redes**. El catálogo no marca premium/free/VIP en ningún campo:
  los 7 servidores son libres. Las 54 redes son todas SlowDNS+SSH con
  nombres de DNS públicos (GoogleDNS 8.8.8.8, CloudflareDNS 1.1.1.1,
  OpenDNS, SafeDNS, FreenomWorldDNS…); el campo `payload` viene vacío
  en las 54: son entradas DNS, no payloads HTTP.
- Un descifrado completo tarda ~6 s en Python puro (3× PBKDF2).

## Uso

```bash
python3 SLOW_DNS.py --url                      # en vivo, dos etapas (imprime JSON)
python3 SLOW_DNS.py --url -o catalogo.json     # guardar
python3 SLOW_DNS.py cuerpo-etapa1.txt          # offline, indice (clave "m")
python3 SLOW_DNS.py cuerpo-etapa2.txt --password '<clave>'
                                               # offline, catalogo (la clave
                                               # la muestra --url en stderr)
python3 SLOW_DNS.py --self-test                # xde/xec, AES-256 (FIPS-197), sobre k() sintetico
```

## Archivos

- `SLOW_DNS.py` — catálogo (stdlib puro Python 3.10+: PBKDF2 de
  `hashlib`, AES-256-CBC implementado en el archivo y verificado byte a
  byte contra PyCryptodome con el catálogo real).
- `SLOW_DNS.png` — icono 512×512 del XAPK.
- Sin `SLOW_DNS_archivos.py`: la app **no tiene formato propio de
  archivo**. El manifiesto no declara intent-filter VIEW para archivos
  ni esquema propio (no hay `slowdns://`), y el DEX no tiene
  importar/exportar perfiles como archivo: los servidores personalizados
  se crean en la interfaz y se guardan en el almacén CHZCORE/MMKV.
- Sin esquemas de texto propios: solo maneja los estándar
  vmess:// / vless:// / trojan:// / ss://, que SP-DECODE ya cubre.

## Pendiente

- Ninguna muestra real pendiente de la app: el catálogo ya se verificó
  en vivo de extremo a extremo. Si el servidor rota la clave del
  catálogo o cambia la URL del índice, el script seguirá funcionando
  mientras la etapa 1 responda (la clave se obtiene de la etapa 1 en
  cada ejecución); si cambia el formato `k()`/xde habrá que
  re-analizar `libchzcore.so`.

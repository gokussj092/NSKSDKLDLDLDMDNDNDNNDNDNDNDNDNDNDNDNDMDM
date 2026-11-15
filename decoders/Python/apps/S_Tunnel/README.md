# S Tunnel 11.1.0 (Play: "MSY VPN TUNNEL") — descifrador de catalogo

Package `com.stunnel.dev`, versionCode 147, versionName 11.1.0, minSdk 32.
Version publica de Google Play (descargada de APKPure; APKMirror no tenia
listado). La app es en realidad **MSY VPN LITE** (MainActivity
`com.msyvpn.lite.MainActivity`); Java/Kotlin puro, sin librerias nativas y
sin splits de arquitectura.

Sin cobertura previa en el repo de SP-DECODE (86 carpetas revisadas).

## Catalogo

```
GET http://servers.jk5.fun/servers.json
```

Peticion exactamente como la app (clase `zh`, caso default; `yh0.f`): GET
plano por Socket TCP, sin TLS, con solo dos cabeceras (`Host: <host>`,
`Connection: close`). Sin autenticacion ni cabeceras propias. La URL esta
ofuscada en el DEX: 35 bytes con XOR 0x4B. El servidor responde HTTP 200,
`Content-Type: application/octet-stream`, `Content-Length: <n>`,
`Connection: close`.

El cuerpo se pasa por `r80.h`:

- Si el primer byte no blanco es `{` (0x7B) o `[` (0x5B), el cuerpo ya es
  JSON en claro.
- Si no, AES-128-GCM/NoPadding sin AAD:
  - clave = SHA-256("MSY_VPN_SECURITY_SALT_2026_@JuanitoProSniff")[:16]
  - IV = primeros 12 bytes del cuerpo
  - ct + tag = resto (tag GCM de 16 B al final)

El JSON es `{v_k7, a_v3, a_vn, a_ur, a_mg, s_nd[], c_mx[]}`: `v_k7` es la
version del catalogo, `a_v3`/`a_vn` la version de la app que lo publico,
`s_nd` los servidores (host `x_h`, IP `x_a`, puertos TCP `x_tp` y UDP
`x_up`, host DNS `x_dn`, host CDN `x_cd`) y `c_mx` las configs/payloads
(tipo `z_t`: tcp/udp/dns/hcr/payload/proxy/ssl/ssl_ws/..., puerto `z_p`,
SNI/host `z_w`, payload HTTP `z_b`, path WS `z_wp`, DNS `z_dn`).

La app tambien puede descargar el catalogo desde los propios servidores
(`zh`): `GET http://<x_h>:<puerto>/servers.json` probando los puertos de
`x_tp`/`x_up` ([80, 8080, 8880, 443, 444, 8443] en el catalogo vivo). El
script prueba primero la URL principal y despues los hosts del catalogo
incluido (mia.jk5.fun, fr1.jk5.fun).

**Quirk de red (verificado en vivo):** el servidor a veces corta la
descarga (cuerpos de 0, 1923, 3539, 4429, 4784, 4949, 5119, 5472 B en vez
de los 6351 B completos). Un cuerpo truncado NO verifica el tag GCM, asi
que el script reintenta el GET completo hasta que el tag verifica (el tag
es la prueba de que el cuerpo esta completo). No se usa Range. El cuerpo
completo es determinista (SHA-256 `8fa9c886f1d787a81885631a24f2d1e24a047ced
01d23c3ef2325ccd83e70d03`); el IV es fijo en el servidor.

## Estado en vivo (2026-11-13)

- Catalogo principal: HTTP 200, 6351 B, abre con el metodo de arriba.
- **Version (v_k7) 49**, a_v3 147, a_vn "11.1.0".
- **2 servidores**: Miami (mia.jk5.fun, 2.26.161.68) y France 1
  (fr1.jk5.fun, 185.253.54.170).
- **19 configs** (8 con payload: WOM Colombia, IMWI #1/#2, Digicel,
  Flow #1-#4; tipos tcp, udp, dns, hcr, payload, proxy, ssl, ssl_ws).
- Asset incluido `res/raw/servers.bin`: **v37**, a_v3 146, a_vn "11.0.0",
  2 servidores, 11 configs (3 con payload).

## Archivos

| Archivo | SHA-256 |
| --- | --- |
| S_Tunnel.py | bea350d7d8ad88b1063be8b54f2ef781ede3a8897d469f37400e5ae4b3ad8764 |
| S_Tunnel.png (512x512) | 78fb01af59279a6b029d2ef37e0329d17d50429e183f9a4c64bd7524ead42a2e |
| servers.bin (asset) | d7212e11e050e5ed758574bd468a1522de4ea558b2bb67c47155bcd9206e00fe |
| catalog_sample.bin (muestra viva v49) | 8fa9c886f1d787a81885631a24f2d1e24a047ced01d23c3ef2325ccd83e70d03 |

`S_Tunnel.py` es Python 3.10+ solo con la biblioteca estandar: AES-128-GCM
esta implementado en Python puro en el mismo archivo (verificado contra
el vector NIST de AES-128-GCM y contra PyCryptodome/cryptography). El
descifrado completo tarda <2 s.

## Uso

```bash
python3 S_Tunnel.py --url --summary -o catalogo.json
python3 S_Tunnel.py --url http://fr1.jk5.fun:8080/servers.json
python3 S_Tunnel.py --asset --summary
python3 S_Tunnel.py servers.bin
python3 S_Tunnel.py --self-test
```

`--url` sin argumento usa `http://servers.jk5.fun/servers.json` (con los
fallbacks de los hosts del catalogo si la principal falla). `--summary`
imprime solo el resumen (version, servidores, configs, configs con
payload). `--self-test` verifica AES-GCM (vector NIST), el descifrado
r80.h, el asset incluido y la muestra viva: 14/14.

## Formatos de archivo y esquemas de texto

- **Sin formato propio de archivo importable.** El manifiesto no declara
  `ACTION_VIEW` ni `ACTION_GET_CONTENT`, no hay extension propia y no
  hay `.sks`. Los configs se crean en la UI y se guardan en el almacen
  interno de la app. Por eso no hay `S_Tunnel_archivos.py`.
- **Sin esquema URI propio.** El manifiesto solo tiene MAIN/LAUNCHER; no
  hay data scheme. No hay `snitunnel://` ni nada equivalente.
- La cadena larga `ww0` (Base64) que se ve en el DEX pertenece al SDK de
  anuncios (clases `ads_mobile_sdk/fc1`, `gx0`), no al catalogo; se
  descarto.

## Pendiente

- Nada para cerrar el metodo: el catalogo esta verificado en vivo de
  principio a fin. Si el servidor rota el salt
  (`MSY_VPN_SECURITY_SALT_2026_@JuanitoProSniff`) o cambia la URL
  (`servers.jk5.fun`), hay que re-analizar `r80.h`/`yh0.f` en el APK nuevo.
- Un archivo `servers.bin` (o un cuerpo cifrado guardado) de una version
  futura de la app serviria para comprobar que el metodo no cambio.

# EDOZ Tunnel Pro 2.4 — decodificador de catálogo

App: **Edoztunnel Pro** (`net.androidtechvilla.edoztunnelpro`), version 2.4,
versionCode 15, minSdk 21, targetSdk 34. APK de un solo archivo (sin splits),
SHA-256 `2f03e0db19edc3ff3fea7932402562ebb9ed065da90dbda4d464a88919999407`.
Sin cobertura previa en el repo de SP-DECODE (86 carpetas revisadas).

## Método (verificado en este APK)

La app es del framework **tcodes** (igual que 24clan VPN Lite) con núcleo
Go (`libgojni.so`) + OpenVPN (`libovpncli.so`) + UDP (`libtechnoreudp.so`).

- **Catálogo gratuito:** `GET https://raw.githubusercontent.com/chrisrepair/Updates/main/Edoztunnel%20Pro%20V7%202024`
  - Descarga con Apache `DefaultHttpClient` + `HttpGet` (`l5/h.java`):
    GET plano, sin headers propios. El servidor devuelve el mismo cuerpo
    con cualquier User-Agent (verificado en vivo).
  - Cuerpo: una línea Base64 → contenedor OpenSSL `Salted__` →
    `EVP_BytesToKey`/MD5 → **AES-256-CBC/PKCS#7** → JSON.
  - Contraseña: **`securedjson`** (`p5/f.java`, campo `f8815a`; es la
    contraseña del formato OpenSSL, no una credencial de cuenta).
    El descifrador de la app es
    `org.apache.commons.ssl.OpenSSL.decrypt("aes256", ...)`.
  - El JSON en vivo trae caracteres de control literales dentro de los
    valores (un salto de línea dentro de un payload); el script usa
    `json.loads(strict=False)` igual que el parser de la app.
  - Esquema: `{Version, Message, Servers[], Tweaks[]}`. Los servidores
    del catálogo gratuito no llevan marca premium/free (los 23 son
    gratuitos). `Tweaks` son las entradas de payload.
  - La app guarda la respuesta cifrada en SQLite (`system.db`,
    `tcodes_table`, fila 1 = gratis, fila 2 = VIP; `m5/a.java`) y la
    descifra al leerla con el mismo `p5/f.a`.
- **Catálogo VIP:** `GET https://raw.githubusercontent.com/chrisrepair/Updates/main/Edoztunnel%20Pro%20VIP%20V3`
  (URL en `p5/d.java`, campo `d`, construida desde bytes). Se descarga
  igual y se descifraría con la misma contraseña, pero **el archivo VIP
  en vivo NO se puede descifrar**: HTTP 200, 1.097 bytes, Base64 → 820
  bytes que no empiezan por `Salted__` (probados además XXTEA,
  AES-CTR/CFB/OFB/GCM y ChaCha20-Poly1305 con las contraseñas
  `securedjson`, `decodepro`, `islam`, `@mtscrypt`, `mtscrypt`).
  El script lo reporta como `VIP_DECRYPT_FAILED` con la evidencia y
  no inventa servidores VIP. Posible causa: el proveedor cambió el
  formato del VIP después de esta versión, o el archivo es un
  marcador. Hace falta un catálogo VIP real de un teléfono (o que el
  proveedor lo vuelva a publicar en formato Salted__).
- **Archivos de configuración:** la app **no tiene formato propio
  importable**. El manifiesto no declara ningún intent-filter
  `ACTION_VIEW` ni esquema URI propio (no existe `edoz://`). Solo
  construye configs `.ovpn` estándar internamente (plantilla
  `assets/udp`, OpenVPN ClientAPI), que SP-DECODE ya decodifica. Por
  eso **no hay `EDOZ_Tunnel_Pro_archivos.py`**.
- **Esquemas de texto:** ninguno propio (solo `vmess://`/`vless://`/
  `ss://`/`trojan://` estándar dentro de los servidores del catálogo).

## Comparación con EDOZ Tunnel (no Pro, 3.7, analizada en paralelo)

Mismo framework tcodes, misma contraseña `securedjson`, mismo formato
Salted__ y misma caché SQLite. Diferencias: la URL del no-Pro es
`Edoztunnnel%20lite%20V7%202024` (con la errata "Edoztunnnel"); su
campo de URL VIP está vacío por defecto y su asset VIP sí descifra
con la misma contraseña; el catálogo incluido (`defconf`) es distinto
(SHA-256 `53a6a2b2…` frente a `cb544a96…` en Pro).

## Resultado en vivo (2026-11-13)

| Fuente | HTTP | Tamaño | Versión | Servidores | Tweaks |
|---|---|---|---|---|---|
| Catálogo gratuito en vivo | 200 | 1.036.137 B | **50.8** | **23** | **1558** |
| Asset `defconf` incluido | — | 378.142 B | 23.08 | 20 | 900 |
| Catálogo VIP en vivo | 200 | 1.097 B | — | **VIP_DECRYPT_FAILED** | — |

## Uso

```bash
python3 EDOZ_Tunnel_Pro.py --url                  # catálogo gratuito en vivo
python3 EDOZ_Tunnel_Pro.py --url -o catalogo.json # ...y guardarlo
python3 EDOZ_Tunnel_Pro.py --vip                  # VIP (falla honesto hoy)
python3 EDOZ_Tunnel_Pro.py --asset                # asset defconf incluido
python3 EDOZ_Tunnel_Pro.py --file respuesta.b64   # catálogo guardado
python3 EDOZ_Tunnel_Pro.py --self-test            # pruebas offline (4/4)
```

Solo stdlib de Python 3.10+ (el AES-256-CBC está implementado en el
script y se verificó byte a byte contra PyCryptodome con el catálogo
en vivo). Un `--url` completo tarda ~30 s (descarga + descifrado puro
en Python). `decode()` + `run()` siguen el formato de proveedor de
SP-DECODE.

## Pendiente

- Un catálogo VIP real (de un teléfono con la app, o republicado en
  formato Salted__) para abrir el VIP; con la respuesta real se
  identifica el cifrado si cambió.
- Ningún archivo exportado real hace falta para el catálogo gratuito:
  está verificado en vivo de extremo a extremo.

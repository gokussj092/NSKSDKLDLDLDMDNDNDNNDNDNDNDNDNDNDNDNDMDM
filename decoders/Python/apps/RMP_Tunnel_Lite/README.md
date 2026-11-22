# RMP TUNNEL LITE RMP-4

Paquete `com.rmptunnel.lite`, build 4. Catálogo completo registrado en Cloud como
`rmp-tunnel-lite`, con fuente HTTPS fija, control administrativo e icono original.
Python 3.10+, biblioteca estándar; no requiere APK ni librerías nativas al ejecutar.

```bash
python server_catalog_decoder.py --download > catalogo.json
python server_catalog_decoder.py copia-cifrada > catalogo.json
python server_catalog_decoder.py --stdin < copia-cifrada > catalogo.json
python file_decoder.py perfil.rmplite
```

Sin argumentos descarga la misma fuente fija. `run(data: bytes) -> str` trabaja
offline; stdout contiene el documento completo y los errores van a stderr con
código 1. Entrada/salida limitadas a 8 MiB.

## Reutilización del motor (sin duplicar lógica)

El catálogo NO tiene codec propio: `codec.py` delega en el módulo ya integrado
de RMP TUNNEL PRO (`../RMP_TUNNEL_PRO/codec.py`), que a su vez delega en el
motor compartido `python-shared-mx-xxtea` (`../Mx_Tunnel_PRO/codec.py` y las
primitivas `../HX_Tunnel_VPN/HX_Tunnel_VPN.py`). La Lite comparte ese motor
con PRO — verificado desde su propio APK, no asumido: su asset `gremlin.json`
es byte-idéntico al de PRO (SHA-256 `03c9cc0f…`, versión 3.8, 40 servidores,
1211 payloads) y sus bytes en vivo son idénticos a los de RMPPRO en vivo.
La única divergencia es la URL fija (`.../RMPLITE` en vez de `.../RMPPRO`),
que vive en `server_catalog_decoder.py`.

Receta compartida (`Hm.a/b/f/g` y `C0195zJ.e`): Base64 estándar, XXTEA con
delta `-1638454863` / `0x9e5729b1`, clave de formato `...|...`
truncada/rellenada a 16 bytes, palabras little-endian y tráiler de
longitud. Conservar `codec.py`, `../RMP_TUNNEL_PRO/codec.py`,
`../Mx_Tunnel_PRO/codec.py` y `../HX_Tunnel_VPN/HX_Tunnel_VPN.py` al
copiar fuera del repositorio.

## Archivos y textos `.rmplite` / `rmplite://`

`file_decoder.py` adapta el entregable del lote 16 (`rmptunnel_files.py`):
una línea de texto hexadecimal → XOR con la clave de formato de 12 bytes
`4%PdXch>fkP]` (índice mod 12, `libputils.so`) → texto JNI modified UTF-8 →
JSON de tweak (`tweak_password`, `tweak_expiry`, `hwid_lock`,
`block_rooted`, `friendly_name`, …). El enlace `rmplite://` lleva el mismo
payload hex, tolerando un marcador opcional `RMPLITE` tras el esquema.
Verificado con oráculo nativo Unicorn en ambas direcciones (dossier
`analysis/com.rmptunnel.lite/4/`); **sin muestra real de `.rmplite`/enlace:
estado VERIFIED_SYNTHETIC**. Los `.ovpn`/`.conf` son passthrough por el
core OpenVPN, sin cifrado RMP. `server.psi` (asset interno Psiphon) es
PARTIAL y no tiene decoder. HMAC de autenticación de conexión:
NOT_OBSERVED (ver dossier).

## Fuentes comprobadas

Fuente recuperada de `OpenVPNClient.z`:
`https://raw.githubusercontent.com/pipoyrichards/RMPSYSTEM/refs/heads/main/RMPLITE`.
La descarga valida TLS, rechaza redirecciones/HTML y aplica timeout y límite de
bytes. El broker Cloud conserva el control de DNS/IP y no acepta URL arbitraria.

Descarga real del **2026-11-22**: HTTP 200, versión **10.3**,
**40 servidores libres (0 premium / 0 vip / 0 private) y 1255 payloads**
(723 808 B, SHA-256 `a977755b…b0`). Re-verificación en vivo el mismo día:
versión **10.4**, mismos conteos (723 984 B, SHA-256 `8f61ee74…55d`); los
bytes siguen siendo idénticos a los de RMPPRO en vivo. Son recuentos
observados, no límites. Las listas Premium/Vip/Private vacías se conservan.

Los consumidores leen directamente los campos JSON internos. Se devuelve todo
el objeto: `Version`, `Changelogs`, `Username`, `Password`, `Free_servers`,
`Premium_servers`, `Vip_servers`, `Private_servers`, `Payloads`, propiedades
desconocidas, vacíos, tipos y duplicados. No se inventan credenciales de
sesión Android.

PNG original exacto de `res/drawable/ic_app_icon.png`, 512×512, 67 222 bytes,
SHA-256 `157565e9f1d1aafdb1b4cb90da76f9e844088137d30e4a285b73d38a1932f0b1`.
Difiere del icono de PRO. Ver [TESTING.md](TESTING.md) y
[manifest.json](manifest.json).

# Tx Tunnel — Tx v2.17 (70)

Paquete `co.strongteam.ospro`, analizado desde el APKS aportado. Lectores offline
de archivos **`.tx`** y del catálogo completo; descargador del origen oficial
fijo. Python 3.10+, PyCryptodome y argon2-cffi, sin APK/SO en runtime.

```bash
python -m pip install -r decoders/Python/apps/Tx_Tunnel/requirements.txt
python decoders/Python/apps/Tx_Tunnel/file_decoder.py perfil.tx
python decoders/Python/apps/Tx_Tunnel/file_decoder.py - < perfil.tx
python decoders/Python/apps/Tx_Tunnel/server_catalog_decoder.py
python decoders/Python/apps/Tx_Tunnel/server_catalog_decoder.py catalogo-cifrado.json
```

Ambos módulos exponen `run(data: bytes) -> str`. El lector de archivos devuelve
`application`, `extension`, `config`; el de catálogo devuelve el documento
entero. Se conservan tipos, claves desconocidas, cadenas que contienen JSON,
campos vacíos y todas las entradas. Los campos EO/DOO se abren por separado.

## Contraseña y formato

**No requiere una contraseña que introduzca el usuario.** El exportador
`NetworkAdapter.u` llama `Libv2ray.eo(Gson(NetworkList))` y guarda `nombre.tx`;
el importador usa `doo`, `Name` y `TunnelType`, sin diálogo de contraseña.
La clave fija y el KDF coinciden con el perfil canónico `txtunnel` de `ultra.py`;
se reutiliza ese KDF en lugar de cambiar las claves de otros proveedores.

EO/DOO usa Argon2id v19 (t=3, m=16384 KiB, p=1, 32 bytes), AES-256-GCM y
AAD igual al salt. Base64 de `salt[16] || nonce[12] || ciphertext || tag[16]`.
**No** utiliza la letra insertada del exportador de MM Tunnel. La app también
acepta JSON directo. No se extrapola el resultado a versiones no analizadas.

`.tx` ya existía. La ruta actual conserva el lector histórico, incluso sus
casos sin AAD, y añade el procesamiento completo de campos del build 70. Un
tag interno inválido o JSON autenticado ambiguo no pasa al lector permisivo.
El bot sigue entrando por `ultra.py`; C8 usa la carpeta de la app. C0 sigue
en **240**, C8 en **250**: no se anuncia un sufijo nuevo.

## Catálogos y cloud

| Fuente comprobada el 2026-10-24 | Versión | Servidores | Redes | Campos cifrados |
|---|---:|---:|---:|---:|
| Asset `assets/configfile.json` | 2.0 | 23 | 66 | 657 |
| Actualizador oficial, HTTP 200 | 65.62 | 27 | 643 | 4231 |

Origen fijo: `https://strongteam.co/api/txtunnel/v1/?appcode=27.0`, GET con
User-Agent **Tx Tunnel**, obtenido del recurso `string/app`. `appcode` es el
tamaño de `base.apk` en MiB redondeado a dos decimales y representado como un
Double: `28308691 / 1048576 -> 27.00 -> 27.0`. No es un identificador personal,
una contraseña, atestación ni cuenta. No se sustituye por códigos adivinados.

Proveedor `tx-tunnel` incorporado al broker fijo, al worker y a los controles
individuales. PNG original de 312819 bytes conservado íntegro, aunque supera
el antiguo umbral de 256 KiB. Catálogo mínimo **40**, **40 fichas**, respetando
la versión efectiva y los switches persistentes. Esto prepara el backend;
su disponibilidad en la VPS requiere desplegarlo por separado.

## Texto y pendientes

La exportación comprobada es un adjunto `.tx`; el texto que lo acompaña solo
invita a instalar la app. No se identificó un esquema propietario `tx://` ni
un cloud de perfiles por token. La base V2Ray contiene VMess, VLESS,
Shadowsocks y Trojan; no se inventan rutas propietarias a partir de esos nombres.
El CLI puede leer el contenido cifrado desde stdin.

**Pendiente una exportación `.tx` real.** Los catálogos son reales; los perfiles
de prueba son sintéticos, generados con una implementación independiente. No
se certifica una importación en teléfono. Herramientas y referencias guardadas
en `scripts/apk_analysis/` y `tests/golden/`; ver ANALYSIS, TESTING y RESTORE.

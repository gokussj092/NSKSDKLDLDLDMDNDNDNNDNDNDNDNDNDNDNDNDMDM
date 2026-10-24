# APNA VPN 3.9 (30)

Paquete `my.teamapna.tunnel`. Catálogo remoto y lector de `.apnavpn` y texto
`apnavpn://`, sin contraseña criptográfica del usuario. Python 3.10+ con
biblioteca estándar; no requiere APK, SO, root ni módulos de pip en producción.

## Termux

El archivo autónomo es `server_catalog_decoder.py`; puede guardarse como
`apna_vpn.py` fuera del repositorio:

```sh
pkg install python
python apna_vpn.py
```

Sin opciones hace GET a la fuente fija oficial y guarda el JSON completo en
`apna_vpn_catalogo.json`, con modo 0600 y sin sobrescribir archivos existentes.
Para otra ejecución, usar otro nombre o mover el archivo anterior:

```sh
python apna_vpn.py --output catalogo_nuevo.json
python apna_vpn.py --summary
python apna_vpn.py --apks 'APNA VPN_3.9.apks' --summary
python apna_vpn.py --input janu.json --output incluido.json
python apna_vpn.py --stdin < janu.json > incluido.json
python apna_vpn.py --file perfil.apnavpn --output perfil.json
python apna_vpn.py --text 'apnavpn://HEX' --output perfil_texto.json
```

Las fuentes locales no acceden a la red. Sin `--output` entregan JSON por stdout;
`--summary` solo admite catálogos y entrega recuentos sin sus credenciales.

## Cobertura verificada el 24 de octubre de 2026

| Fuente real | Versión | Free_servers | Payloads | JSON completo |
|---|---|---|---|---|
| `assets/janu.json` del APK | 289 | 19 | 491 | 210815 bytes |
| GET oficial de `OpenVPNClient.r()` | 456 | 18 | 493 | 208498 bytes |

Los dos documentos completos coinciden byte por byte con la referencia Java y
como objetos completos con el worker aislado. En ambos están vacíos
`Premium_servers`, `Vip_servers` y `Private_servers`; se conservan las diez
secciones y sus valores. El `UpdaterLink` del asset está desactualizado:
el descargador utiliza exclusivamente la URL fija que realmente llama el APK.

Catálogos: Base64 → XXTEA modificado, delta `0x9E5729B1`, little-endian y tamaño
original en la última palabra. Perfiles: hexadecimal → XOR fijo nativo → UTF-8
modificado JNI → JSON. No hay MAC en estos formatos; la validación estructural
no equivale a autenticación criptográfica. Ver [ANALYSIS.md](ANALYSIS.md).

La app descifra el perfil antes de leer `tweak_password`. Ese valor controla
la importación, no deriva la clave de cifrado. El lector conserva la contraseña,
expiración, HWID, restricciones y campos desconocidos dentro del JSON recuperado.
El formato de archivos/texto está confirmado por DEX/SO, cinco vectores de la
función ARM64 original y perfiles sintéticos completos comparados con Java;
**aún falta una exportación `.apnavpn` real y una prueba Android**.

## Integración

Rama `feat/mm-tunnel-1-10-11-1-decoders`, PR #99. Tarjeta pública `apna-vpn`,
icono PNG original, broker HTTPS fijo y control individual persistente. Se
respeta el interruptor global `CLOUD_SERVER_VPN_ENABLED` y los estados previos.
Catálogo mínimo 42, 43 fichas; C0 conserva 240 rutas y C8 tiene 252, incluida
`.apnavpn` en los metadatos remotos como Cloud, sin anunciar soporte Android
offline. `run()` del catálogo y `file_decoder.py` no descargan contenidos.

No se incluyen APK/SO/DEX, catálogos reales ni credenciales en Git. El resultado
integra el código; no implica despliegue VPS, fusión, APK nueva o novedades C11.

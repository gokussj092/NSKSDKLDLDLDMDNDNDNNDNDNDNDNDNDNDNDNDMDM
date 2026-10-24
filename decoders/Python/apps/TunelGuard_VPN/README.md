# TunelGuard VPN 12.8

Paquete `tunnel.guard.vpn`, versionCode **128**. Lectores Python de `.tgv` y del
catálogo actual, integrados en SP-DECODE Cloud, rama
`feat/austroplus-vpn-13-0-1-decoders`, PR #96. No necesitan APK ni SO al ejecutar.

## Estado comprobado

- **Archivos `.tgv`**: importador y exportador del APK identificados; documentos
  sintéticos completos comprobados con JDK y descifrado ARM64 real. Worker
  aislado y petición autenticada al worker HTTP real devuelven el mismo JSON.
  No se proporcionó una exportación real independiente ni se certifica writer.
- **Catálogo incluido en el APK**: documento completo igual al oracle Java,
  Version `0.1`, 1 servidor, 1 ajuste (`Tweaks`), 10 campos codificados no vacíos.
- **Catálogo externo pendiente**: el enlace exacto recuperado del APK responde
  **HTTP 404**. Se consultó con autorización explícita y se confirmó mediante
  las APIs de archivo y Contents de GitHub. No hay respuesta remota válida que
  permita afirmar cuántos servidores/usuarios están disponibles actualmente.
- La ficha e icono se añaden al catálogo público mínimo **17**, con descarga
  remota **desactivada**. El broker no incorpora una fuente no validada a su
  allowlist ni ofrece un interruptor administrativo para activarla prematuramente.
- No se identificó una segunda fuente separada de usuarios. Se mantienen todas
  las secciones y credenciales que formen parte del documento, sin fabricar
  listas ni limitarse a los primeros registros.

## Uso

Python >=3.10 y `pip install -r requirements.txt`. Para uso independiente,
conservar `TunelGuard_VPN/` y la carpeta hermana `HTTP_FenixVPN/` con `codec.py`
y `field_names.json`: solo se reutilizan sus validadores, límites y renderer.

```bash
python file_decoder.py archivo.tgv > perfil.json
python file_decoder.py < archivo.tgv > perfil.json
python server_catalog_decoder.py copia_cifrada.txt > catalogo.json
python server_catalog_decoder.py --stdin < copia_cifrada.txt > catalogo.json
python server_catalog_decoder.py > catalogo.json
```

La última orden intenta la fuente fija; **actualmente falla porque devuelve
404**. Archivo/stdin y `run(data: bytes) -> str` no consultan la red. No se
aceptan ubicaciones arbitrarias. Fuente original recuperada de `lp1`:
`https://raw.githubusercontent.com/eddyme23/octo/refs/heads/main/xxTG.js`.

## Método del catálogo

`lp1.l1I1Il1` contiene la copia inicial. `fj0` valida la forma `STGCM2.TG.`;
`eBase64.nDecryptConfig`, `libfrkudp.so:0xd81c8`, confirma AES-256-GCM, nonce12,
tag16 y AAD **`STGCM2.TG.`**, incluido el último punto. Los dos componentes
binarios usan URL-Base64 sin padding. La función nativa **0xdae20**, ejecutada
independientemente, recupera los 32 bytes de la constante de esta compilación
con la tabla de `0x4d5c8`. No depende de la versión ni de contraseñas del usuario.
Los controles Android de paquete/firma del llamador no forman parte de esa clave.

Tras autenticar, `t17.l11I1Il` aplica XOR por unidades UTF-16 con máscaras
30482 / 14551 / 22566 / 65535. `field_names.json` registra por separado:

| Sección | Transformación |
| --- | --- |
| Metadatos raíz | Nueve campos XOR (`version`, updater e IDs), con sus tipos y demás claves intactos |
| `message` | `u8:` + Base64 UTF-8 si tiene ese marcador; XOR en la otra variante observada |
| `Servers` | 32 campos XOR confirmados por `MainActivity.U/Z`, incluidos OpenVPN, V2Ray, UDP, Hysteria 2, WireGuard, CloudFront y GCP |
| `Tweaks` | Ocho campos XOR; `Name`, país, modo, booleanos y claves desconocidas permanecen con sus tipos originales |

Los nombres/información/banderas de servidores son texto directo; los campos
`Flag`/`Info` de ajustes sí se transforman. No se aplica XOR indiscriminadamente
al JSON. Se conservan listas vacías válidas, campos opcionales nulos/vacíos,
secciones desconocidas y valores que la UI sustituiría por sus predeterminados.
No se expanden enlaces ni se ejecutan configuraciones del resultado.

## Método de archivos .tgv

El manifest declara `.tgv`; `ExportActivity.I1lI11l` forma el objeto `TGV_CONFIG`
y llama `TekProtect.nEncryptUserConfig` (`0xde90c`). `MainActivity.E/C` usa
`nDecryptUserConfig` (`0xdfbac`). El formato es Base64 estándar de
**IV16 + AES-128-CBC/PKCS7**, con los primeros 16 bytes de la constante recuperada
por `0xe06ec`. No es el sobre GCM del catálogo ni usa el cifrado de preferencias.

El texto exterior pasa por JNI `GetStringUTFChars`/`NewStringUTF`: usa Modified
UTF-8/CESU-8 para los pares sustitutos. Se comprobaron emojis y texto no latino
contra el descifrador ARM64 y el oracle Java. Los 16 campos de perfil registrados
utilizan doble Base64 de Android con UTF-8 y saltos de línea. `Server` contiene
JSON serializado: se descifran sus campos con el mismo esquema de servidores y
se conserva su tipo **cadena JSON**, todas sus claves y sus tipos internos;
solo cambia la representación de espacios al serializar ese JSON interior.

`MyPass`, `isPassON`, `DeviceID`, `ExpireDate`, requisitos de Play Store/root y
mensajes se conservan. En esta compilación son metadatos comprobados por la app
**después** del descifrado; no derivan la clave AES. El lector no modifica esas
políticas ni necesita un formulario de contraseña/HWID para abrir este formato.
El sobre CBC no tiene autenticación propia: padding y JSON válidos no equivalen
a una garantía criptográfica de integridad. No se ofrece exportación o roundtrip.

## Integración y disponibilidad

`.tgv` se registra como ruta C8 de archivos en el worker y como detección Cloud
en `CloudFileFormats.kt`; no se modifica la matriz C0 ni se añade descifrado
Android. El reconocimiento de esta extensión nueva requiere un cliente compilado
con ese registro y el backend actualizado. No se publica APK en esta entrega.
El worker de catálogo `tunelguard-vpn` permite abrir copias existentes, mientras
la ficha pública mantiene `remote:null`/`decodeEnabled:false` por el 404 real.

El icono es el WebP original del lanzador, recurso `0x7f100003`, 192×192,
`base.apk:res/mipmap-xxxhdpi-v4/ic_launcher.webp`. Se conserva el archivo exacto
y un PNG de píxeles RGBA idénticos, sin redimensionar. Hashes en `manifest.json`.

Límites: archivo 5 MiB, catálogo y salida del lector 8 MiB, profundidad 64;
Cloud conserva su presupuesto de salida 4 MiB. Un exceso o campo corrupto
produce error explícito; no hay recorte ni resultado parcial silencioso.
No se imprimen valores de entrada en errores ni se publican catálogos reales,
APKs, SOs o credenciales en Git. No se fusiona ni despliega esta rama, y las
novedades C11 no se publican automáticamente. Ver `TESTING.md`.

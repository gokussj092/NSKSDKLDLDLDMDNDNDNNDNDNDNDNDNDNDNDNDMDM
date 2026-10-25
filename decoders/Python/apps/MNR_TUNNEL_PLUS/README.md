# MNR TUNNEL PLUS 3.1 (31)

Paquete `com.hamo.vpn`. Catálogo, `.stp`, texto cifrado del portapapeles e
importación online `mnrtunneludp://` incorporados en PR #99. Sin contraseña
criptográfica del usuario o HWID; se conservan sus valores y restricciones.

## Termux: script autónomo

`codec.py` funciona como un único script, sin carpetas hermanas o APK. La copia
descargable se llama `mnr_tunnel_plus.py`:

```sh
pkg install python clang make
python -m pip install pycryptodome==3.23.0
python mnr_tunnel_plus.py
python mnr_tunnel_plus.py --file perfil.stp --output perfil.json
python mnr_tunnel_plus.py --file texto_cifrado.txt --output texto.json
python mnr_tunnel_plus.py --online 'mnrtunneludp://ID_DE_10_CARACTERES' --output online.json
```

Reemplazar el marcador del último comando por una referencia real de diez
caracteres alfanuméricos. También acepta ese ID sin prefijo con `--online`.
Sin argumentos descarga la fuente fija y guarda `mnr_catalogo.json`; perfiles
usan `mnr_perfil.json` por defecto. Las salidas son 0600 y no se sobrescriben.
No registrar ni compartir resultados que contengan credenciales.

Fuentes locales, sin red:

```sh
python codec.py --input catalogo_cifrado.txt --summary
python codec.py --apks MNR.apks --summary
python file_decoder.py perfil.stp
python file_decoder.py - < texto_cifrado.txt
python server_catalog_decoder.py catalogo_cifrado.txt
```

## Formatos

El exterior de catálogo usa F5.a con constante `devpro`; `.stp`, texto y cuerpo
del objeto online usan `demondevs`. Cada par de símbolos representa un byte
del Base64; se abre con AES-256-CBC/PKCS7, IV cero y SHA-256 del hexadecimal
mayúsculo de los bytes UTF-8 de la constante. No se usa una clave personal.

Los campos conocidos de `Servers` y `Networks` llevan otra capa, F5.g, alfabeto
U+2000..U+200F y constante interna diferente. **No quitar espacios Unicode**:
son dígitos del ciphertext. La salida conserva nombres, IDs, puertos, flags,
campos desconocidos y estructuras originales. `wsPayload` y `wsProxyPayload`
son booleanos, no texto cifrado. `PREFIX` y `DNS_RESOLVER_MANUAL` sí se abren.

G5.f exporta archivo y portapapeles con nombres como `http_p`, `v2_c`, `udp_s`.
G5.h sube un perfil con `CPayload`, `V2Ray`, `UdpServer`, etc. Ambos JSON se
devuelven enteros, sin convertir uno en el otro. MainActivity.F descifra antes
de comprobar `isPassON` / `MyPass`, fecha y DeviceID.

## Catálogo e importación online

GET fijo:
`https://raw.githubusercontent.com/buttacuore2025/up/refs/heads/main/plusfast`.
No usar `plusfastapp`, que corresponde a actualización de la aplicación.
Incluido real **1.0 / 9 servidores / 112 redes**; remoto real **14.4 / 14 / 119**.
Los dos documentos enteros, con **1149 campos cifrados**, coinciden con JDK
independiente y worker. Descarga real de la CLI guardada y comparada completa.

El exportador genera `mnrtunneludp://` + ID aleatorio de diez caracteres y
lo guarda como objeto `.sky` en el bucket fijo `hamovpn.firebasestorage.app`.
Firebase normaliza el doble slash: la ruta real es `mnrtunneludp:/ID.sky`.
La importación consulta metadatos, toma el primer `downloadTokens` y descarga
ese objeto. No lista el bucket, busca IDs ni modifica objetos.

API nueva `POST /api/v1/decode/import/mnr`, cuerpo
`{"reference":"mnrtunneludp://...","consent":true}`. Requiere sesión existente.
El endpoint de texto existente también reconoce el enlace completo; enviar
ese enlace a Descodificar solicita la importación de ese único objeto. Un ID
sin prefijo se admite en el endpoint dedicado/CLI, no como texto genérico.
El broker usa TLS, DNS IPv4 pública fijada, límites y rechazo de redirecciones.
El mismo interruptor persistente controla catálogo y red online; archivo/texto
local no dependen de él. El worker sigue offline.

**Pendientes:** `.stp` exportado real, referencia online real y Android/Termux
físicos. El flujo online se comprobó con respuestas sintéticas y su código
original; no se certifica acceso al bucket o sus permisos actuales sin un ID
real. No se añaden credenciales Firebase ni se elude autenticación.

Hasta 8 MiB en lector/descarga, 256 KiB para metadatos online, profundidad 64 y
200000 nodos JSON. Worker conserva 4 MiB de salida; texto, 250000 caracteres.
AES-CBC no tiene MAC: padding/estructura no equivalen a autenticación.
El helper heredado `ConfigParser` menciona `.sft`/GCM XML, pero no se identificó
una ruta activa de interfaz hacia él; no se publica `.sft` por esa constante.
Los protocolos V2Ray comunes mantienen sus rutas anteriores.

Icono PNG original del APK (su imagen dice MNR TUNNEL PRO). Ficha y controles
existentes reutilizados. C0 240, C8 254, mínimo 46 / 46 fichas. Sin cambio de
diseño Android, fusión, despliegue, APK o C11. Ver ANALYSIS y TESTING.

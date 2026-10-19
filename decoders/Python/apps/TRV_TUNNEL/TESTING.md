# Verificación — TRV TUNNEL 2.4

Fecha: 2026-10-19. Paquete `com.trv.tunnel`, versionCode 15.
Rama `feat/cloud-c8-vps-installer-updater`, PR #94.
No se incluyen APK, bibliotecas, catálogos reales ni cuentas en Git o en el ZIP
entregable. Las muestras sintéticas usan datos ficticios y dominios `.invalid`.

## Origen analizado

| Elemento | SHA-256 |
|---|---|
| ZIP recibido | `d70a5fbf5eca988941c9100b6e205ecaf83da026b98e9c2cbecdc1a15bbe8ebd` |
| Contenedor APKS | `bcffd98fec6d45062f744e513f5343a78cfe5d273c206dd8a626a101a45c1dd3` |
| `base.apk` | `46c30fa59308f219b53bb106e98c1e8ec994de8f61e4eead0edb357f405667bf` |
| `libputils.so` ARM64 | `08becdcbfc897eb5b910f23f4dda64a3cfb9cfd43b949e84e9c9c3884bc32abe` |
| Java `AbstractC0282Km` original obtenido con JADX | `86edf6dd34efc62db75588f1eff0bd3b8fe2f2c7d5a62b0262722b6cf0acaf15` |
| `assets/gremlin.json`, 294232 bytes | `8a7fc98caccfe8399ae26c9f66ce219d09dfbe033208235215de2f133305cb89` |
| Respuesta remota, 316552 bytes | `79acf19daff92d2d0ef19bb36656c205516babb926060b5fb222842b2c5bf6b8` |
| Icono original, 76923 bytes | `cca027b2a1a69d1cb0a70b77ea902175f93ddf9c405bdbcaf196a0135770526e` |

Icono: `base.apk:res/drawable/ic_app_icon.png`, 512 × 512, conservado byte por
byte en la carpeta de TRV y en `cloud/web/public/server-vpn-icons/trv-tunnel.png`.
No necesita modificar tamaño, colores o transparencia.

## Comprobación independiente del catálogo

Se resolvieron 1779 constantes LSParanoid del APK recibido con sus clases
originales. Se extrajo y ejecutó la clase Java `AbstractC0282Km`, incluidos sus
métodos de cifrado y descifrado XXTEA. Para el lanzador se sustituyó únicamente
el decoder Base64 `X70.m` por el estándar Java y se resolvió la constante de
clave. No se usó el lector Python para generar la salida de referencia.

| Catálogo | Free | Premium | Vip | Private | Payloads | JSON completo |
|---|---:|---:|---:|---:|---:|---|
| Recurso del APK | 27 | 0 | 0 | 0 | 630 | Igual al Java de TRV |
| Descarga real | 32 | 0 | 0 | 0 | 671 | Igual al Java de TRV |

La salida del lector ocupa 283548 bytes local y 304622 bytes remota, incluyendo
su salto final. Se compararon todos los campos, credenciales, configuraciones,
tipos y propiedades desconocidas, sin limitar el número de entradas.
Ambos catálogos reales pasaron además por `decode_provider_catalog` y su
subproceso Cloud con igualdad completa e `isPartial=false`.

El CLI final sin argumentos se ejecutó con `python -S`: descargó directamente
el catálogo de TRV y se comparó con la referencia Java. La descarga no usa el
catálogo local como fallback ni requiere APK o paquetes instalados.

## Comprobación independiente de `.hxt`

Se siguieron `OpenVPNClient.D0`, `X`, `onActivityResult(1001)`, el importador
`B` y los exportadores de tweaks de `KJ`. La exportación escribe directamente
el texto hexadecimal de `PUtils.pEncrypt`, no un contenedor ni un prefijo de
longitud. Se inspeccionaron `pEncrypt/pDecrypt` y las funciones de representación
hexadecimal de la biblioteca entregada.

Se ejecutó la función ARM64 original `xorWithKey` en Unicorn, con adaptadores
únicamente para copia y memoria de `std::string`. Las operaciones XOR, selección
de clave y módulo por posición se ejecutaron desde los bytes originales. Se
contrastaron entradas que cruzan bloques y todos los valores byte 0–255.
No se ejecutó la app ni se modificaron sus comprobaciones de firma o paquete.

Java `DataOutputStream.writeUTF`, descartando sus dos bytes de longitud,
produjo el texto modificado JNI de los fixtures. Es únicamente un oráculo de
codificación: **esos dos bytes no forman parte del archivo `.hxt`**.
Incluye caracteres suplementarios/emojis, multilineales, PIN, HWID, caducidad,
flags representados como cadenas, estructuras desconocidas y tipos mixtos.

Se confirmó que las primitivas y constantes recuperadas de TRV coinciden con
los dos motores HX ya presentes. Se reutilizan sin cambios; no se copia su
algoritmo a un tercer motor en Git. El ZIP incluye copias byte por byte de esas
fuentes como dependencias locales de los adaptadores. Sus hashes constan en el
manifest y se comprueban en las pruebas.

## Pruebas sin red en CI

`tests/golden/trv_tunnel_vectors.json` contiene dos perfiles sintéticos, un
catálogo sintético completo, vectores XXTEA cortos/largos y documentos inválidos
cifrados con las rutinas originales. `tests/golden/trv_tunnel_oracle.java`
conserva el Java reproducible de cifrado/descifrado y el oráculo JNI.
El APK y las herramientas de análisis nativo no son dependencias de CI.

`tests/test_trv_tunnel.py` verifica la igualdad completa de perfiles y catálogo,
CESU-8, preservación de flags/cuentas/cadenas de configuración, campos desconocidos,
BOM, mayúsculas hex, saltos de línea y Base64 sin padding. Rechaza formatos
cruzados, URLs usadas como archivo, hexadecimal impar, UTF-8 no válido, UTF-8 de
cuatro bytes en un texto JNI, surrogates sin pareja, JSON duplicado/incorrecto,
NaN/Infinity, profundidad, estructuras inválidas y entradas mayores de 8 MiB.

Las pruebas CLI copian los dos adaptadores y sus dos dependencias a una carpeta
fuera del repositorio y ejecutan `python -S`, tanto con archivo como por stdin.
Se verifican errores sin stdout parcial ni valores privados en stderr.
La descarga simulada comprueba URL fija, user-agent, timeout, límite, HTTP,
compresión, redirecciones, HTML y errores de red. Los tests Cloud ejecutan los
subprocesos reales y conservan la ruta `.hxt` compartida y sus 246 extensiones.

El test Node de broker añade TRV a la verificación de host, query, TLS e IP
pública anclada. No se admiten URLs del usuario ni redirecciones a otro dominio,
HTTP o query diferente. Los tests de versión, iconos originales y CLI QA se
actualizan a la versión pública mínima 5 con incremento monotónico.

```bash
python -m unittest discover -s tests -p 'test_trv_tunnel.py' -v
python -m unittest discover -s tests -v
python -m unittest discover -s cloud/workers/python -v
python -m unittest discover -s cloud/infra/vps/tests -v
cd cloud/web
npm test
npm run build
```

Resultados locales finales: suite principal **607 pruebas**, satisfactorias
con **9 omisiones existentes** por muestras privadas ausentes; **10** pruebas
específicas TRV incluidas. Worker **11**, VPS/QA **39**, gates Cloud **4**,
Node **61**, sin fallos; `npm run build` correcto. La paridad histórica C2
se conserva, incluidos los motores HX y Royal. No se reescriben snapshots
ni se ocultan los avisos históricos de drift.

## Límites de lo comprobado

No se recibió una exportación `.hxt` real independiente; la evidencia de archivos
es el exportador original, los vectores nativos y los fixtures sintéticos.
`exporterCertified` permanece en false. No se ensayaron importaciones en UI,
conectividad VPN ni vigencia de cuentas. No se elimina PIN, HWID, caducidad o
root de una exportación. La ausencia de MAC en XOR/XXTEA impide certificar la
autenticidad del documento completo; solo se validan los errores detectables.

`hxt://` aparece como literal, sin un importador de perfiles para ese esquema;
no se añade un lector de enlaces supuesto. Los recursos internos Psiphon y el
registro de dispositivos no se tratan como nuevos formatos de usuario.
Otras versiones pueden cambiar URL, claves, esquema o codificación.

Sin despliegue, fusión, publicación APK ni cambios Android/interfaz administrativa.

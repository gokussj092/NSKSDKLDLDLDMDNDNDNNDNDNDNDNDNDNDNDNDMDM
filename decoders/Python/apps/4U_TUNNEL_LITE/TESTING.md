# Verificación — 4U TUNNEL LITE 2.2

Fecha: 2026-10-19. Paquete `com.forutunnel.lite`, versionCode 13.
Rama `feat/cloud-c8-vps-installer-updater`, PR #94.
No se incluyen APK, bibliotecas, catálogos reales ni cuentas en Git o en el ZIP
entregable. Las muestras sintéticas usan datos ficticios y dominios `.invalid`.

## Origen analizado

| Elemento | SHA-256 |
|---|---|
| ZIP recibido | `e2a4b27f7351ba42803f81cc8515502da79b45cef5587e4077463aaf1127625b` |
| Contenedor APKS | `2a655d9daa1770f4389d01df05fb93d05d490036c97551850538d4972e72bed7` |
| `base.apk` | `afa1fcb3f99292162d9a727e05c8bcdbe1b51a3d74b17a004d103c319dfb3f3a` |
| `libputils.so` ARM64 | `592e4e1d49071e31b0c1936abd580c0cd179518540a636f78e23a92a99fa72aa` |
| Java `AbstractC0282Km` original obtenido con JADX | `8c39de0e92f68293c1c71ae8751be0f3fc0c0b52ea19d54ff3aa5d73b28e90f2` |
| `assets/gremlin.json`, 321840 bytes | `66a8d116ec0b7a5eda0f9615ca6dc9175f02d232c14b42b38141120c571a3cd6` |
| Respuesta remota, 367868 bytes | `bd88f637be80d0d63ddf8895bbb2b8e2b84779ae9e2a4e6c3b9b14088a4f5526` |
| Icono original, 20114 bytes | `b6f76cff34d9f242b3b21ed3c13eedaf917adbfae8eb96f017e76003ab9cbb58` |

Icono: `base.apk:res/drawable/ic_app_icon.png`, 512 × 512, conservado byte por
byte en la carpeta de 4U y en `cloud/web/public/server-vpn-icons/4u-tunnel-lite.png`.
No necesita modificar tamaño, colores o transparencia.

## Comprobación independiente del catálogo

Se resolvieron 1779 constantes LSParanoid del APK recibido con sus clases
originales. Se extrajo y ejecutó la clase Java `AbstractC0282Km`, incluidos sus
métodos de cifrado y descifrado XXTEA. Para el lanzador se sustituyó únicamente
el decoder Base64 `X70.m` por el estándar Java y se resolvió la constante de
clave. No se usó el lector Python para generar la salida de referencia.

| Catálogo | Free | Premium | Vip | Private | Payloads | JSON completo |
|---|---:|---:|---:|---:|---:|---|
| Recurso del APK | 25 | 0 | 0 | 0 | 635 | Igual al Java de 4U |
| Descarga real | 33 | 0 | 0 | 0 | 707 | Igual al Java de 4U |

La salida del lector ocupa 304412 bytes local y 346444 bytes remota, incluyendo
su salto final. Se compararon todos los campos, credenciales, configuraciones,
tipos y propiedades desconocidas, sin limitar el número de entradas.
Ambos catálogos reales pasaron además por `decode_provider_catalog` y su
subproceso Cloud con igualdad completa e `isPartial=false`.

El CLI final sin argumentos se ejecutó con `python -S`: descargó directamente
el catálogo de 4U y se comparó con la referencia Java. La descarga no usa el
catálogo local como fallback ni requiere APK o paquetes instalados.

## Comprobación independiente de `.4ulite`

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
codificación: **esos dos bytes no forman parte del archivo `.4ulite`**.
Incluye caracteres suplementarios/emojis, multilineales, PIN, HWID, caducidad,
flags representados como cadenas, estructuras desconocidas y tipos mixtos.

Se confirmó que las primitivas y constantes recuperadas de 4U coinciden con
los dos motores HX ya presentes. Se reutilizan sin cambios; no se copia su
algoritmo a un tercer motor en Git. El ZIP incluye copias byte por byte de esas
fuentes como dependencias locales de los adaptadores. Sus hashes constan en el
manifest y se comprueban en las pruebas.

## Pruebas sin red en CI

`tests/golden/four_u_tunnel_lite_vectors.json` contiene dos perfiles sintéticos, un
catálogo sintético completo, vectores XXTEA cortos/largos y documentos inválidos
cifrados con las rutinas originales. `tests/golden/four_u_tunnel_lite_oracle.java`
conserva el Java reproducible de cifrado/descifrado y el oráculo JNI.
El APK y las herramientas de análisis nativo no son dependencias de CI.

`tests/test_four_u_tunnel_lite.py` verifica la igualdad completa de perfiles y catálogo,
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
subprocesos reales y conservan la ruta `.4ulite` compartida y sus 246 extensiones.

El test Node de broker añade 4U a la verificación de host, query, TLS e IP
pública anclada. No se admiten URLs del usuario ni redirecciones a otro dominio,
HTTP o query diferente. Los tests de versión, iconos originales y CLI QA se
actualizan a la versión pública mínima 6 con incremento monotónico.

```bash
python -m unittest discover -s tests -p 'test_four_u_tunnel_lite.py' -v
python -m unittest discover -s tests -v
python -m unittest discover -s cloud/workers/python -v
python -m unittest discover -s cloud/infra/vps/tests -v
cd cloud/web
npm test
npm run build
```

## Política de iconos aplicada a todas las aplicaciones

Se retira el filtro de 256 KiB en el backend y las dos barreras de bytes/Base64
Android. El PNG original se conserva, verifica por SHA-256 y guarda cifrado sin
reescribirlo. `ServerVpnIconPolicy.java` calcula un muestreo de visualización
hasta 512 píxeles de lado; dimensiones grandes no excluyen una imagen válida.
La caché admite el presupuesto general de 6 MiB ya presente en el transporte
C++, sin añadir un nuevo límite específico por app.

El icono Royal original de 415664 bytes se publica con checksum intacto y su
ficha visible; `decodeEnabled=false` porque falta la validación de su catálogo.
Los tests Node ejercitan la respuesta real de icono con más de 350000 caracteres
Base64. El arnés `ServerVpnIconPolicyHarness.java` compila y ejecuta la clase
Java de producción con el PNG real, tamaños superiores a 1 MiB, dimensiones
extremas y entradas inválidas. El test host requiere JDK; en un contenedor sin
Java se omite únicamente esa ejecución, manteniendo los controles de contrato.
No es una prueba de UI Android ni una compilación local del APK.

El cambio Android se autoriza exclusivamente para iconos por la indicación
expresa del usuario del 2026-10-19. Requiere instalar una APK con ese ajuste:
el cliente anterior conserva su barrera de 256 KiB. Actualizar clientes antes
de activar en producción el catálogo que incluye imágenes grandes. No se ha
desplegado ni publicado una APK como parte de este trabajo.

## Resultados locales finales

Suite principal **620 pruebas**, satisfactoria con **9 omisiones existentes**;
**11** controles 4U y **2** de política de iconos incluidos. Worker **11**,
VPS/QA **39**, gates Cloud **4**, Node **63**, sin fallos; `npm run build` correcto.
El arnés Java compiló y ejecutó la política de producción, incluyendo el PNG
Royal original. No se compiló ni ensayó el APK completo localmente. Se conserva
la paridad de textos heredados y los snapshots C2, sin ocultar su drift histórico.

## Límites de lo comprobado

No se recibió una exportación `.4ulite` real independiente; la evidencia de archivos
es el exportador original, los vectores nativos y los fixtures sintéticos.
`exporterCertified` permanece en false. No se ensayaron importaciones en UI,
conectividad VPN ni vigencia de cuentas. No se elimina PIN, HWID, caducidad o
root de una exportación. La ausencia de MAC en XOR/XXTEA impide certificar la
autenticidad del documento completo; solo se validan los errores detectables.

`4ulite://` se conserva como entrada de compatibilidad de SP-DECODE, sin
afirmar que el APK implemente ese handler ni descargar referencias Cloud. Los recursos internos Psiphon y el
registro de dispositivos no se tratan como nuevos formatos de usuario.
Otras versiones pueden cambiar URL, claves, esquema o codificación.

Sin despliegue, fusión, publicación APK ni cambios de diseño/interfaz administrativa.
Android solo cambia su política de imágenes y caché, sin incorporar descifradores.

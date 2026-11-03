# Wolf Custom VPN v2.8.1.2 (13)

Paquete `core.vpn3jx.xtreme`, nombre confirmado **Wolf Custom VPN**. Se analizó
el build **13 / v2.8.1.2**, obtenido de APKPure y confirmado por el manifiesto
binario el 2026-10-31. La ficha del espejo mostraba versiones antiguas; la
compatibilidad aquí corresponde al archivo realmente analizado.

## Uso

Python 3.10+, `pip install -r requirements.txt`. Desde esta carpeta:

```bash
python server_catalog_decoder.py > servidores.json
python server_catalog_decoder.py copia_cifrada.txt > servidores.json
python server_catalog_decoder.py --stdin < copia_cifrada.txt
python file_decoder.py perfil.wolf > perfil.json
python file_decoder.py < perfil.wolf > perfil.json
```

Sin argumentos, el lector remoto descarga su única fuente fija. Archivo y stdin
son rutas sin red. Conservar la carpeta hermana `HTTP_FenixVPN/` con `codec.py`
y `field_names.json`, usados para validación JSON y límites comunes. El lector
de archivos antiguos necesita además `decoders/Python/ultra.py` y Argon2.
Los catálogos y perfiles modernos no necesitan el APK, root ni contraseña del
usuario. No se publica un nuevo esquema de enlaces.

## Método recuperado

El método moderno difiere del Wolf histórico de `ultra.py`. Las dos primitivas
nativas usan **Base64 estándar de nonce12 || ciphertext || tag16**,
**AES-256-GCM sin AAD**, y una clave fija de 32 bytes utilizada directamente.
No se descodifica la clave como Base64 ni se deriva con SHA-256 o Argon2.

| Función y biblioteca | Entrada de función ARM64 | Dirección de clave | Uso |
| --- | --- | --- | --- |
| `AndroidLibXrayLite.Decrypt`, `libgojni.so` | `0x100ad80` | `0x363810` | Sobre de catálogo/perfil y campos del motor V2Ray |
| `main.Decrypt2`, `libgoinjector.so` | `0x2b2580` | `0x87e7a` | Campos del inyector HTTP |

Las constantes recuperadas están en `codec.KEY` y `codec.INJECTOR_KEY`.
`Payload`, `CustomProxy` y `SNI` aceptan ambas variantes autenticadas, ya que el
asset combina los dos motores. El resto de campos usa la primera. Se manejan
también ajustes anidados `Servers[].V2ray` y `Servers[].UDPHysteria` según los
modelos del APK. Las claves y tipos desconocidos, nombres, puertos, indicadores,
valores vacíos y estructuras adicionales se conservan completos. `URI` es un
indicador booleano y no se intenta descifrar. Tampoco se interpreta `Info` como
ciphertext por parecer Base64.

La app admite campos en texto claro. El lector conserva esos valores, pero un
campo conocido que tiene la sintaxis de un sobre moderno debe autenticar con
una clave admitida. Si falla, se rechaza el documento; no se presenta un
ciphertext como si se hubiera descifrado correctamente.

`ConfigUpdate.b` obtiene la fuente de una cadena LSParanoid y realiza GET:
`https://strongteam.co/api/wolfcustom/newv1.txt`. La constante se verificó tras
resolver las cadenas con `scripts/apk_analysis/paranoid_strings.py`.
`Hometab.Companion.a` llama a `Libv2ray.decrypt`; el lector de catálogo incluido
abre `assets/configfile.json`. Las primitivas se verificaron mediante
desensamblado Go/ARM64, lectura de constantes con hashes fijados y un oráculo
JCA independiente; no se afirma ejecución completa de la app en Android.

La fuente histórica `https://strongteam.co/api/wolf/` queda fuera del nuevo
descargador y del broker. No se usa como fallback. La descarga usa HTTPS fijo,
25 segundos en Python, máximo 8 MiB, HTTP 200, `Accept-Encoding: identity` y
ninguna redirección. El agente `Wolf Custom VPN` funcionó en la comprobación
real. El broker Node fija una IPv4 pública y aplica los controles existentes.

## Archivos .wolf y compatibilidad

`NetworkAdapter.v` exporta el JSON Gson de un **NetworkList**, lo cifra con
`Libv2ray.encrypt` y escribe `.wolf` (`application/x-wolf`). El lector devuelve
ese perfil con sus campos descifrados, sin renombrarlos.

Cloud añade un override de `.wolf` en C8 y el dispatcher `ultra.run` delega a
esta carpeta. Si no autentica el sobre moderno, se conserva el lector Wolf
Argon2/GCM anterior; si el sobre autentica y falla su JSON o un campo, no se
intenta otra receta. `.wolftunnel` conserva su ruta anterior. C0 sigue en
**240** formatos, el inventario efectivo en **254**; hay **28 overrides C8**.
El formato público `.wolf` recibe el nombre del motor nuevo sin añadir otra
extensión. No se exige contraseña, HWID ni claves personales.

Se probaron perfiles sintéticos de ambos motores y el contrato de exportación
observado en el DEX. **No se obtuvo una exportación real independiente del
teléfono ni se certifica el exportador o una conexión VPN**.

## Integración y resultados

Tarjeta, icono y control individual: `wolf-custom-vpn`. El worker expone
`run(data: bytes) -> str`, sin red dentro del proceso de descifrado. La salida
conserva el JSON completo, incluyendo `Servers`, `Networks` y claves extras.
La revisión pública sube de **58 a 59**, con **51 tarjetas**. Se conservan los
cambios recientes de Jireh/JyFast y sus pruebas de recuperación de caché.
El catálogo lógico actual es compartido por V1/V2; esta integración no cambia
sus contratos ni altera los interruptores persistentes del panel.

| Muestra real | Version | Servidores | Redes | Campos cifrados comparados con JCA |
| --- | --- | ---: | ---: | ---: |
| Asset incluido | 1.01 | 1 | 3 | 31 |
| Primera captura remota | 6.44 | 164 | 2014 | 13260 |
| Captura remota posterior | 6.45 | 164 | 2015 | 13267 |

Las tres muestras coinciden íntegramente entre Python, JCA y worker aislado,
con `isPartial=false`. El proveedor actualizó el catálogo durante el trabajo;
estos recuentos son observaciones, no constantes del lector. La salida del
worker de 6.45 ocupa **2656081 bytes** y su respuesta completa **5175411 bytes**,
dentro de los límites existentes (4 MiB de texto, 6 MiB de respuesta interna).
El CLI real descargó 6.45 y el gateway aceptó esa respuesta completa del worker
con HTTP 200 usando un transporte interno simulado.
No se aumentan límites para hacer pasar la muestra.

Se aprobaron **34 pruebas Python** y **140 Node** dirigidas a esta integración,
regresiones Jireh/JyFast, inventarios, metadatos, controles y broker. No se
ejecutó la suite completa, compilación Android ni despliegue VPS. El transporte
Node al proveedor se validó con DNS/HTTPS simulados; la descarga real se
comprobó con Python. Ver `TESTING.md` y `manifest.json`.

El launcher original del APK es WebP: se conserva intacto como
`Wolf_Custom_VPN.webp`. Su copia PNG de 192×192 es una conversión sin pérdida de
píxeles, idéntica en esta carpeta y en `cloud/web/public/server-vpn-icons/`.
No se redibuja ni se sustituye la marca. Git contiene iconos, código y vectores
sintéticos; los APKs y catálogos/credenciales reales quedan fuera.

## Recuperación persistente

El XAPK original está guardado como
`Wolf-Custom-VPN-2.8.1.2-build13.xapk`, Library ID
`libfile_2db70a357b208191b86e7a7f93ed05de`. El procedimiento sin dependencia del
entorno temporal está en `docs/cloud/WOLF_CUSTOM_VPN_HANDOFF_2026_10_31.md`.
Las herramientas `wolf_native_constants.py` y `wolf_verify.py` quedan
versionadas para reconstruir y repetir las comprobaciones.

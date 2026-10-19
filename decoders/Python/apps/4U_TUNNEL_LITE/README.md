# 4U TUNNEL LITE 2.2

Aplicación analizada: `com.forutunnel.lite`, versión **2.2**, versionCode **13**.
El APK exporta/importa **tweaks `.4ulite`** y descarga un catálogo remoto completo.
La extensión se confirmó en el constructor y el manifest del APK.

| Archivo | Uso |
|---|---|
| `file_decoder.py` | Abrir archivos `.4ulite` o su texto hexadecimal guardado; offline |
| `server_catalog_decoder.py` | Descargar y descifrar el catálogo remoto, o leer una copia cifrada |
| `4U_TUNNEL_LITE.png` | Icono original del APK, sin modificaciones |
| `manifest.json`, `TESTING.md` | Compatibilidad, evidencias y pruebas |

## Ejecución

Python 3.10 o posterior, **solo biblioteca estándar**. No requiere APK, Android,
Java, paquetes pip, identificación de dispositivo ni una cuenta VPN.

Desde esta carpeta dentro del repositorio, o desde la carpeta completa del ZIP:

```bash
python file_decoder.py ejemplo.4ulite > perfil.json
python file_decoder.py < ejemplo.4ulite > perfil.json
python server_catalog_decoder.py > catalogo.json
python server_catalog_decoder.py copia-cifrada.json > catalogo.json
python server_catalog_decoder.py --stdin < copia-cifrada.json > catalogo.json
```

Sin argumentos, el lector de catálogo descarga la URL fija original. Con archivo
posicional o `--stdin`, trabaja offline, sin extensión obligatoria para las copias.
Los errores van a stderr con código 1; stdout contiene únicamente el JSON completo
si termina correctamente. Ambos lectores ofrecen `run(data: bytes) -> str`, offline.

**Motores compartidos:** el análisis nuevo del Java y de `libputils.so` de 4U
confirmó las mismas primitivas, constantes y representación de texto que HX
Tunnel VPN Hx-Build14. Se reutilizan sus motores sin modificarlos ni duplicar
algoritmos en Git. El repositorio resuelve esas dependencias automáticamente.

Para ejecutar fuera del repositorio, el ZIP incluye dos copias idénticas de las
fuentes compartidas: `hxt_file_codec.py` y `hxt_catalog_codec.py`. **Conservarlas
junto a los dos lectores.** Son dependencias del paquete; los puntos de entrada
para 4U son los de la tabla. No es necesario adjuntar el APK al ejecutar nada.
Los SHA-256 de esas fuentes constan en `manifest.json`.

## Archivos `.4ulite`

En este APK, `OpenVPNClient.D0` es `.4ulite`. `OpenVPNClient.X()` llama a
`PUtils.pEncrypt(context, JSONObject.toString())` y escribe directamente los bytes
de esa cadena, tanto por MediaStore como por FileOutputStream.
`onActivityResult(1001)` lee el texto y llama a `PUtils.pDecrypt` antes de importar.

El formato confirmado es:

1. Texto JSON codificado como **UTF-8 modificado de JNI / CESU-8**, incluyendo
   pares surrogate para caracteres como emojis.
2. XOR repetido con el material fijo de `libputils.so:xorWithKey`.
3. Representación hexadecimal, dos dígitos por byte.

No es AES ni XXTEA, no contiene ZIP, no usa el PIN para derivar la clave y no
lleva un prefijo binario de longitud. El hexadecimal exportado tiene longitud
par. La salida conserva todos los valores y tipos: `friendly_name`, `payload`,
`sausage`, `host`, `port`, `dothost`, `method`, `category`, `query`, `sslws`,
`message` y propiedades desconocidas, incluidas las de bloqueo:
`tweak_password`, `tweak_expiry`, `hwid_lock`, `mobile_data_only`, `block_rooted`.
No cambia cadenas como `"true"` a booleanos ni fragmenta configuraciones.

Un `.4ulite` contiene el **tweak seleccionado**, no necesariamente un servidor o
las cuentas del catálogo. El lector devuelve lo almacenado; no inventa campos
faltantes ni incorpora valores de otro catálogo.

El importador de la app valida PIN, caducidad, HWID y root después del descifrado.
Estos lectores recuperan sus valores para inspección; no modifican políticas ni
crean un archivo desbloqueado. No se ensayó la importación en la interfaz Android.

## Catálogo remoto

URL original recuperada de `OpenVPNClient.z()`:
`https://ctxrelay.online/updater/08f9aa63574a055cffdac66783b05b`.
El lector no admite una URL proporcionada por argumentos. La descarga usa HTTPS
con validación TLS, límite de bytes y timeout; rechaza redirecciones y HTML.
No reproduce el registro de dispositivos ni las solicitudes de publicidad de la app.

El formato procede de `AbstractC0282Km`:

- Base64 estándar, aceptando saltos de línea y padding omitido por Android.
- XXTEA con palabras little-endian, tráiler de longitud y delta propio
  **`-1638454863` / `0x9e5729b1`**.
- Clave de formato `Princie!`, truncada/rellenada a 16 bytes según el Java.
- Objeto JSON completo. Los consumidores de 4U leen directamente los campos
  internos: no hay una segunda capa de cifrado para cada campo.

Se conservan `Version`, `Changelogs`, `Username`, `Password`, todas las listas
`Free_servers`, `Premium_servers`, `Vip_servers`, `Private_servers`, `Payloads`
y cualquier propiedad adicional. No se mezclan tweaks privados del teléfono.
El recurso inicial del APK es `assets/gremlin.json`; su extensión `.json` no
significa que sea texto plano. `assets/server.psi` es material interno de
Psiphon y no un formato adicional de exportación de usuario.

**Verificación real del 2026-10-19:**

| Origen | Servidores | Payloads/tweaks |
|---|---:|---:|
| Catálogo incluido en el APK | 25 | 635 |
| Descarga remota real | 33 | 707 |

Los tres grupos Premium/Vip/Private estaban vacíos en ambas muestras; se
conservan igualmente. Los recuentos corresponden a esa descarga y pueden cambiar.
El JSON íntegro de ambos orígenes coincide con el Java original extraído de 4U;
también atravesó el proceso aislado Cloud sin truncamiento.

Por compatibilidad con SP-DECODE también se admite `4ulite://` seguido del
mismo hexadecimal en este lector de archivos. El dispatcher global de textos
conserva su motor histórico, cuya recursión de campos es diferente.
No representa una URL de descarga. El APK analizado abre archivos mediante
`content://` y `file://`; no se identificó un handler Android de ese esquema.
No se intenta descargar una referencia ni se descifran recursivamente cadenas
que solo parecen hexadecimales: se preservan valores como `deadbeef`.

## Cloud y compatibilidad

`4u-tunnel-lite` se registra en el bridge privado y en el broker de URL fija, con
icono original y metadatos públicos. La lista pública sube a **versión 6**.
Una instalación que tenga `CLOUD_SERVER_VPN_CATALOG_VERSION` configurado debe
incrementarlo a un entero mayor que el anterior y **al menos 6** al actualizar.
El interruptor `CLOUD_SERVER_VPN_ENABLED` sigue desactivado por defecto.

C8 dirige `.4ulite` a este lector, sustituyendo la ruta genérica anterior;
un archivo con prefijo explícito usa ese mismo lector. La ruta global de
textos heredada se conserva. El C0 histórico conserva
sus 240 rutas y C8 mantiene 246 extensiones, pues `.4ulite` ya existía. Los
motores HX permanecen sin modificaciones. Los metadatos y tipos se conservan,
sin aplicar el descifrado heurístico de campos del motor genérico anterior.

Por indicación del usuario, todos los iconos originales se conservan aunque
superen el antiguo límite. Royal ya tiene su imagen en el catálogo público,
con descifrado desactivado mientras no se valide su endpoint. El ajuste Android
se limita a la carga y caché de imágenes, manteniendo el diseño y los motores
fuera de la app. Política y orden de actualización en
`docs/cloud/SERVER_VPN_NEXT_CHAT_GUIDE.md`.

Límites de estos adaptadores: 8 MiB de entrada/salida; profundidad JSON 64.
Cloud conserva su límite global de salida de 4 MiB y sus procesos aislados.
Errores detectables de formato, JSON, tamaño o codificación hacen fallar el
comando entero. XOR y XXTEA no autentican los datos: no se afirma verificar su
procedencia criptográfica ni la vigencia de cuentas.

**Límite de validación de archivos:** no se recibió un `.4ulite` real exportado.
Se verificó el exportador del APK y se ejecutó su XOR nativo para generar
perfiles sintéticos, contrastando el texto JNI con Java. `exporterCertified`
sigue en `false`. Evidencias completas en [TESTING.md](TESTING.md).

Trabajo en `feat/cloud-c8-vps-installer-updater`, PR #94. Sin fusión,
despliegue VPS ni publicación de APK.

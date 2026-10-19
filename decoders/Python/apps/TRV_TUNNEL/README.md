# TRV TUNNEL 2.4

Aplicación analizada: `com.trv.tunnel`, versión **2.4**, versionCode **15**.
El APK exporta/importa **tweaks `.hxt`** y descarga un catálogo remoto completo.
No se identificó una extensión `.trv` ni un enlace de perfil Cloud independiente.

| Archivo | Uso |
|---|---|
| `file_decoder.py` | Abrir archivos `.hxt` o su texto hexadecimal guardado; offline |
| `server_catalog_decoder.py` | Descargar y descifrar el catálogo remoto, o leer una copia cifrada |
| `TRV_TUNNEL.png` | Icono original del APK, sin modificaciones |
| `manifest.json`, `TESTING.md` | Compatibilidad, evidencias y pruebas |

## Ejecución

Python 3.10 o posterior, **solo biblioteca estándar**. No requiere APK, Android,
Java, paquetes pip, identificación de dispositivo ni una cuenta VPN.

Desde esta carpeta dentro del repositorio, o desde la carpeta completa del ZIP:

```bash
python file_decoder.py ejemplo.hxt > perfil.json
python file_decoder.py < ejemplo.hxt > perfil.json
python server_catalog_decoder.py > catalogo.json
python server_catalog_decoder.py copia-cifrada.json > catalogo.json
python server_catalog_decoder.py --stdin < copia-cifrada.json > catalogo.json
```

Sin argumentos, el lector de catálogo descarga la URL fija original. Con archivo
posicional o `--stdin`, trabaja offline, sin extensión obligatoria para las copias.
Los errores van a stderr con código 1; stdout contiene únicamente el JSON completo
si termina correctamente. Ambos lectores ofrecen `run(data: bytes) -> str`, offline.

**Motores compartidos:** el análisis nuevo del Java y de `libputils.so` de TRV
confirmó las mismas primitivas, constantes y representación de texto que HX
Tunnel VPN Hx-Build14. Se reutilizan sus motores sin modificarlos ni duplicar
algoritmos en Git. El repositorio resuelve esas dependencias automáticamente.

Para ejecutar fuera del repositorio, el ZIP incluye dos copias idénticas de las
fuentes compartidas: `hxt_file_codec.py` y `hxt_catalog_codec.py`. **Conservarlas
junto a los dos lectores.** Son dependencias del paquete; los puntos de entrada
para TRV son los de la tabla. No es necesario adjuntar el APK al ejecutar nada.
Los SHA-256 de esas fuentes constan en `manifest.json`.

## Archivos `.hxt`

En este APK, `OpenVPNClient.D0` es `.hxt`. `OpenVPNClient.X()` llama a
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

Un `.hxt` contiene el **tweak seleccionado**, no necesariamente un servidor o
las cuentas del catálogo. El lector devuelve lo almacenado; no inventa campos
faltantes ni incorpora valores de otro catálogo.

El importador de la app valida PIN, caducidad, HWID y root después del descifrado.
Estos lectores recuperan sus valores para inspección; no modifican políticas ni
crean un archivo desbloqueado. No se ensayó la importación en la interfaz Android.

## Catálogo remoto

URL original recuperada de `OpenVPNClient.z()`:
`https://trmrelay.store/updater/b67b57c85f49c34ee09fd87f2d6915`.
El lector no admite una URL proporcionada por argumentos. La descarga usa HTTPS
con validación TLS, límite de bytes y timeout; rechaza redirecciones y HTML.
No reproduce el registro de dispositivos ni las solicitudes de publicidad de la app.

El formato procede de `AbstractC0282Km`:

- Base64 estándar, aceptando saltos de línea y padding omitido por Android.
- XXTEA con palabras little-endian, tráiler de longitud y delta propio
  **`-1638454863` / `0x9e5729b1`**.
- Clave de formato `Princie!`, truncada/rellenada a 16 bytes según el Java.
- Objeto JSON completo. Los consumidores de TRV leen directamente los campos
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
| Catálogo incluido en el APK | 27 | 630 |
| Descarga remota real | 32 | 671 |

Los tres grupos Premium/Vip/Private estaban vacíos en ambas muestras; se
conservan igualmente. Los recuentos corresponden a esa descarga y pueden cambiar.
El JSON íntegro de ambos orígenes coincide con el Java original extraído de TRV;
también atravesó el proceso aislado Cloud sin truncamiento.

El literal `hxt://` permanece en el constructor, pero no se encontró un handler
que descifre texto después de ese esquema. El manifest abre `.hxt` mediante
`content://` y `file://`; no se añade un protocolo de texto no demostrado.

## Cloud y compatibilidad

`trv-tunnel` se registra en el bridge privado y en el broker de URL fija, con
icono original y metadatos públicos. La lista pública sube a **versión 5**.
Una instalación que tenga `CLOUD_SERVER_VPN_CATALOG_VERSION` configurado debe
incrementarlo a un entero mayor que el anterior y **al menos 5** al actualizar.
El interruptor `CLOUD_SERVER_VPN_ENABLED` sigue desactivado por defecto.

`.hxt` ya usa el motor compartido HX en C8 y acepta estos mismos bytes TRV;
no se sustituye esa ruta ni se registra una extensión ficticia. C0 conserva sus
240 rutas y C8 mantiene 246 extensiones efectivas. Royal y sus pendientes de
publicación no cambian. No se modifica Android ni la interfaz administrativa.

Límites de estos adaptadores: 8 MiB de entrada/salida; profundidad JSON 64.
Cloud conserva su límite global de salida de 4 MiB y sus procesos aislados.
Errores detectables de formato, JSON, tamaño o codificación hacen fallar el
comando entero. XOR y XXTEA no autentican los datos: no se afirma verificar su
procedencia criptográfica ni la vigencia de cuentas.

**Límite de validación de archivos:** no se recibió un `.hxt` real exportado.
Se verificó el exportador del APK y se ejecutó su XOR nativo para generar
perfiles sintéticos, contrastando el texto JNI con Java. `exporterCertified`
sigue en `false`. Evidencias completas en [TESTING.md](TESTING.md).

Trabajo en `feat/cloud-c8-vps-installer-updater`, PR #94. Sin fusión,
despliegue VPS ni publicación de APK.

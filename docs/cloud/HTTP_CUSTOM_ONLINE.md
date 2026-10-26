# HTTP Custom online — descarga única de .hc

Implementación del 2026-10-26 en la rama
`feat/ha-tunnel-plus-1-7-1-decoders` / PR #102. No es el protocolo firmado de
HTTP Injector Cloud ni requiere sus claves. Los lectores `.hc`, HCCFG y HCX4
permanecen sin cambios. Tampoco es un catálogo Server VPN: no se añade otra
ficha de servidores.

## Fuentes examinadas

- `https://link.playsmarty.uk/`: permite compartir URL o subir `.hc`; declara
  un uso y caducidad automática de 30 minutos. Las dos referencias facilitadas
  devolvieron HTTP404 y una página que no distingue entre inexistencia, uso y
  expiración. No se vuelve a consultar una referencia agotada para descifrar.
- `https://cloudvpn.mrfrankofc.com/`: la página y el bundle público anuncian
  subida de `.hc`, códigos de seis caracteres, `maxDownloads` y
  `expiresMinutes`. El formulario público usa `/api/public/upload`; comprobar
  estado usa `/api/public/status?code=...`. La descarga publicada es `/{code}`.
  Un intento de subir un **HCX4 sintético sin credenciales reales**, con límite
  uno y cinco minutos, devolvió HTTP500. No se obtuvo un enlace nuevo válido.

**Estado:** contrato de transporte y delegación probados; falta comprobar una
importación completa con un enlace real vigente. Los enlaces proporcionados no
contienen ahora un archivo recuperable. Un mock no demuestra que el proveedor
esté disponible. No se afirma que la web añada otro cifrado ni que se haya
superado una restricción del proveedor.

## Flujo estable en Android

1. El usuario pega una referencia HTTPS de los dos hosts admitidos.
2. Android pide al broker la descarga, con sesión y consentimiento. El broker
   descarga una vez y devuelve los **bytes cifrados originales** en Base64.
3. Android llama a `/api/v1/decode/file`, formato `hc`. Si el motor exige
   contraseña, HWID o ambos, se usa el diálogo HC ya existente. La segunda
   llamada al lector usa el mismo array de bytes y no abre otra vez el enlace.
4. Éxito, error, contraseña incorrecta o cancelación borran el array de bytes y
   el de contraseña. No se cachea el archivo en Redis, historial ni disco.
   El historial mantiene el comportamiento existente para el resultado que el
   usuario acaba de descifrar. Una contraseña incorrecta no se intenta otra vez
   automáticamente. Para otra importación de un link agotado hace falta un
   enlace nuevo o disponer del archivo original.

El prompt se inserta en la fuente Cloud generada por Gradle. Se conservan las
nueve fuentes UI C0 congeladas y sus hashes. No se añaden algoritmos, claves
secretas ni conexiones a los proveedores en el APK: Kotlin reconoce las
referencias; JNI solo habla con la API SP-DECODE. La cancelación no inicia una
segunda descarga. Se conservan los errores del lector y el aviso localizado de
contraseña incorrecta cuando se envió una contraseña sin HWID.

## Contrato API

`POST /api/v1/decode/import/http-custom`, con bearer de sesión válido:

```json
{"reference":"https://cloudvpn.mrfrankofc.com/Ab12Cd","consent":true}
```

Respuesta HTTP200, cifrada todavía:

```json
{"apiVersion":"v1","status":"success","kind":"encrypted_file","format":"hc","sourceBytes":123,"dataBase64":"..."}
```

Los clientes deben pasar ese contenido a `/api/v1/decode/file` con los campos
`credentials.password` / `credentials.hwid` solo si el motor los pide. Así no
consumen otro uso del enlace para un requisito de credenciales. El límite de
entrada sigue en 8 MiB; el límite JNI de 12 MiB se aplica solo a esta respuesta
Base64. El límite habitual de resultados descifrados no cambia.

También se aceptan referencias completas en `/api/v1/decode/text`, con los
mismos campos opcionales de credenciales HC. Esta es una conveniencia para
clientes que ya conocen las credenciales; los clientes interactivos deben usar
la descarga previa para conservar los bytes durante el diálogo.

HTTP404/410 del proveedor se transforma en HTTP410
`REMOTE_CONFIG_UNAVAILABLE`: no existe, está usado, fue retirado o ha expirado.
No se puede afirmar cuál de esas causas produjo un 404. HTTP429/5xx o timeout
son indisponibilidad remota, no fallo criptográfico. HTML con HTTP200 se
rechaza como `REMOTE_RESPONSE_INVALID`, no como un archivo HC.

## Transporte y controles

- HTTPS, sin userinfo, puertos, IP literales, query, fragmentos ni rutas extra.
- Mr Frank: seis caracteres URL seguros (alfanuméricos, `_` o `-`). Playsmarty: alias de 1–64 caracteres
  alfanuméricos, `_` o `-`.
- Hasta tres redirects, exclusivamente entre referencias de esos dos hosts.
  Las URL arbitrarias que permite acortar Playsmarty **no** convierten el broker
  en un descargador general. Un destino fuera de esta lista se rechaza antes
  de abrir un socket; no se siguen redirects hacia almacenamiento desconocido.
- DNS IPv4 público comprobado y fijado al socket TLS en cada salto; no IPv6
  privado, cookies, identificadores del dispositivo ni cabeceras del usuario.
- Sin reintentos automáticos de descarga, ni siquiera ante un error de red.
  No se puede saber si el proveedor ya consumió un enlace cuando la red falla.
- Cuerpo acotado, timeout, sin descompresión HTTP ni contenido ejecutado.
- No se guardan URL, tokens ni bytes en métricas. El lease de sesión se libera
  tanto en éxito como al expirar o fallar la fuente.

Panel: nuevo ID fijo `hc-cloud`, etiqueta **HTTP Custom Cloud**, con interruptor
persistente que conserva los estados existentes. `CLOUD_HTTP_CUSTOM_IMPORT_ENABLED`
permite desactivar toda esa importación; por defecto está activa cuando la API
está configurada. Usa el mantenimiento de archivos, no el de HTTP Injector.
No se ha desplegado ni modificado el VPS en esta entrega.

## Catálogo y compatibilidad

Versión mínima **53**, **48 fichas Server VPN**, C0 **240**, C8 **254**.
`onlineReferenceFormats` y `onlineReferencesSchemaVersion=1` son campos
aditivos separados: los APK antiguos siguen validando `textFormats` como antes.
El nuevo Android valida solo los dos prefijos públicos y guarda esos metadatos
junto al catálogo cifrado. Se actualizan sus textos admitidos sin publicar
endpoints privados, scripts ni claves. Un APK anterior necesita actualización
para reconocer estos enlaces y mantener los bytes en el diálogo; actualizar
solo el VPS no añade ese flujo al cliente antiguo.

## Validación

```sh
cd cloud/web
node --test tests/*.test.mjs
cd ../..
python -m unittest tests.test_http_custom_899 tests.test_cloud_c2_hc \
  tests.test_cloud_c0_inventory tests.test_cloud_c8_android_input_routes \
  tests.test_cloud_c8_user_errors tests.test_cloud_c2_text -q
```

- **339 pruebas Node**, incluidas nueve nuevas: transporte, redirect permitido,
  SSRF/DNS, bytes binarios, límites, HTML, expiración, sesión/consentimiento,
  delegación íntegra al worker HC y metadatos compatibles.
- **36 pruebas Python** de motor HC, contratos, errores, rutas e inventario/UI.
- Cuatro casos Android añadidos: misma entrada en la petición de credenciales,
  descarga única, borrado de bytes al terminar/cancelar, error por expiración y
  referencias estrictas. **Suite instrumentada API35 aprobada en Actions
  40343506902**, commit de implementación `3c1b7e16`. Las diez comprobaciones de
  ese commit finalizaron aprobadas. Este entorno local no tiene Android SDK.
- Pendiente: enlace real nuevo y prueba física Android/Termux. Un enlace
  agotado no se revive ni se eluden los límites configurados por su propietario.

Archivos del proveedor, cuerpos HTTP, referencia original y captura de subida
quedan fuera de Git. Conservar este documento después de una limpieza local.

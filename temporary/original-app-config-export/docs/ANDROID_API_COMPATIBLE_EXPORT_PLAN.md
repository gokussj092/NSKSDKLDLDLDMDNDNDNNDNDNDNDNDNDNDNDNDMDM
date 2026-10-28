# Integración de exportación compatible: propuesta QA Android/API

Fecha: 2026-10-27, America/Tijuana. Propuesta basada en el código de esta rama,
no implementación ni despliegue. El propietario pidió explicar cómo integrarlo
para pruebas. Solo se modifica documentación y el reporte manual NPV.

## Comportamiento solicitado

Después de descifrar, el usuario ve su JSON y pulsa **Exportar**. El diálogo
conserva JSON y texto ordenado; para un resultado compatible sustituye la fila
de texto original descifrado por **Exportar para HTTP Custom**, **Exportar para
Dark Tunnel**, **Exportar para HTTP Injector** o **Exportar para NPV Tunnel**.
La elección abre el selector de destino con la extensión de la aplicación.
El diálogo de copiar no cambia. La selección de la aplicación procede del
formato autenticado por la API, no solamente del nombre del archivo subido.

El perfil funcional propuesto `original-app-open-v1` genera una salida abierta,
sin contraseña de importación, vinculación HWID ni destinatario ECDH, cuando
el adaptador haya sido validado para esa variante. Conserva hosts, puertos,
usuarios, contraseñas de conexión, payloads, perfiles y opciones. No modifica
restricciones remotas ni deduce que borrar un flag invalida una protección.
La expiración u otras políticas no representables requieren soporte explícito;
el sistema no las descarta silenciosamente al pedir quitar contraseña/HWID.

## Estado real del código

| Punto | Estado observado |
| --- | --- |
| `SpDecodeApp.kt`, diálogo `dialog="export"` | Tres filas: `JSON`, `ORDERED`, `ORIGINAL`; esta última es texto descifrado, no el archivo VPN original |
| `CompleteResultCard.kt` | El botón Exportar ya abre ese diálogo; se puede reutilizar |
| `MainActivity.kt` | Guarda con `CreateDocument` como JSON/texto y convierte a UTF-8; necesita una ruta de bytes para `.hc/.dark/.ehi/.npvs` |
| `DecodeView` / `SecureDecodeHistory` | Resultado textual; no contienen el contenedor original, credenciales ni contexto criptográfico de exportación |
| `CloudDecodeClient.Decoded` | Solo `rawText` y `sourceBytes`; `decodeFile` devuelve `String` y desecha metadatos adicionales |
| `c3-gateway.mjs` | `validatePayload` de archivo solo admite `format`, `dataBase64`, `credentials`; cualquier opción nueva exige ampliar explícitamente el contrato |
| `engine.py` | Subproceso aislado, credenciales por stdin, directorio temporal eliminado al terminar; `exporterCertified:false` no es una capacidad de exportación específica |
| `spdecode_transport.cpp` | Petición máxima 12 MiB y respuesta normal máxima 6 MiB; no se debe duplicar sin límite el JSON más un artefacto Base64 |

No se deben usar `ResultPresentation.formatted`, el árbol JSON visible,
el texto ordenado ni un resultado con credenciales enmascaradas como fuente
del cifrado. Pueden perder tipos, estructuras y metadatos. El adaptador toma
los bytes originales y el documento autenticado completo dentro del worker.

## Primera beta recomendada: preparar durante el descifrado

Se propone reutilizar `POST /api/v1/decode/file` con una opción **opt-in**
`compatibleExport:{"profile":"original-app-open-v1"}`. Un interruptor servidor
nuevo, por defecto desactivado, limita esta extensión a sesiones QA admitidas.
Los clientes antiguos siguen usando el contrato anterior sin esta opción.
El alcance inicial son archivos subidos; resultados de catálogo, enlaces y
texto sin su fuente íntegra no reciben capacidad automáticamente.

1. La app manda el archivo y las credenciales por el canal existente.
2. El worker autentica y descifra completamente. Si falla, no devuelve JSON
   parcial ni artefacto exportable.
3. En ese mismo trabajo, con las credenciales ya disponibles, el adaptador
   reconstruye el formato abierto y vuelve a autenticar/leer el resultado
   **sin las credenciales de entrada**. Compara las conexiones antes/después.
4. Si pasa, la respuesta incluye el JSON habitual y `compatibleExport` con
   los bytes Base64, extensión, nombre seguro, hash y perfil utilizado.
5. Android verifica hash, longitud, formato esperado y vínculo con ese
   resultado; guarda únicamente los bytes del artefacto en RAM.
6. Pulsar Exportar guarda esos bytes directamente mediante Storage Access
   Framework. No necesita otra petición ni guardar la contraseña/private key
   en una sesión de exportación.

La generación opcional puede fallar por variante o política no soportada sin
destruir un descifrado válido. En ese caso, `compatibleExport.status` es
`unavailable`, con un código fijo y sin payload. Se conserva el JSON recibido.
Si el feature flag está apagado, el contrato antiguo se conserva.

Ejemplo **propuesto**, con valores de demostración:

```json
{
  "apiVersion": "v1",
  "status": "success",
  "rawText": "{...}",
  "isPartial": false,
  "compatibleExport": {
    "status": "ready",
    "profile": "original-app-open-v1",
    "targetAppId": "http-custom",
    "extension": ".hc",
    "filename": "config-SP-DECODE.hc",
    "mimeType": "application/octet-stream",
    "sourceSha256": "<hash del original>",
    "sha256": "<hash del artefacto>",
    "sizeBytes": 1234,
    "dataBase64": "<bytes del archivo>",
    "protections": {
      "filePasswordRequired": false,
      "hwidRequired": false,
      "recipientPrivateKeyRequired": false
    }
  }
}
```

Esas tres propiedades describen el resultado que verificó el servidor; el
cliente no puede imponerlas para saltarse una comprobación. Un simple
`unlock:true`, una extensión o el booleano global `exporterCertified` no
sustituyen la capacidad específica.

Para la beta: límite de artefacto 1 MiB, además de límites por adaptador;
la respuesta JSON serializada completa debe caber en los 6 MiB del JNI.
Si no cabe, se devuelve el resultado de descifrado sin el artefacto y con
`EXPORT_TOO_LARGE`. No se trunca el archivo ni el JSON, ni se aumenta el límite
especial de MKK para esta función. Una descarga diferida autenticada puede
evaluarse más adelante si hacen falta archivos mayores.

El almacén RAM de Android se vincula a `DecodeView.id`, hash de origen y perfil;
TTL propuesto 5 minutos y presupuesto total 4 MiB, sin `SavedStateHandle`,
historial ni copias en preferencias. Los buffers se liberan/limpian al vencer,
eliminar el resultado o cerrar la sesión. La limpieza de arrays es de mejor
esfuerzo; no se promete borrar todas las copias de Strings o del recolector.
Al restaurar un resultado antiguo sin artefacto, mostrar «Vuelve a descifrar
el archivo para exportarlo». El JSON histórico por sí solo no basta.

## Contraseña, HWID y private key

El objetivo automático se aplica **después del descifrado autenticado**:

- **HTTP Custom:** abrir con password/HWID usados por el usuario, reconstruir
  la variante sin esas exigencias y rederivar todas las claves/AAD afectadas.
  El laboratorio actual valida únicamente HCX4/HCCFG10/n11/899 **sin** esas
  protecciones de entrada y usa una referencia abierta privada. La integración
  necesita un adaptador sin dependencia de muestras con credenciales y pruebas
  reales de contraseña, HWID y ambos antes de activar esa ampliación.
- **NPV Tunnel:** el lector ya admite passphrase y recipient v5/v6 con
  `credentials.recipientKey`. Android ya selecciona la identidad mediante
  `NpvsRecipientPicker`; `npvs_identity.agreement` valida pareja/fingerprint o
  acuerdo ligado al archivo y autentica la DEK. Una public key sola identifica
  al destinatario y no abre el contenido. Tras una apertura completa, el nuevo
  adaptador deberá reconstruir NPVO1 desde los registros crudos; no copiar
  recipient, password, private key ni shared secret a la salida. La identidad
  existente del usuario permanece en su vault. El escritor actual solo acepta
  v5 app-key sin destinatarios y política vacía; passphrase, recipient/v6 y
  políticas adicionales son **ampliaciones pendientes de prueba**.
- **Dark Tunnel / HTTP Injector:** conservar únicamente las variantes
  auditadas y las salidas abiertas comprobadas. Si un método nuevo exige una
  credencial, se añade la apertura y conversión correspondiente; no se asume
  compatibilidad por haber recibido algún JSON.

No se conserva una contraseña de apertura para después. Se usa en el trabajo
actual, y se descarta junto con los temporales al terminar. Los bytes privados
no entran en argv, variables de entorno, logs, diagnósticos ni telemetría.
La creación de Strings y subprocesos impide prometer zeroization perfecta.

## Matriz de habilitación propuesta

| Aplicación | Salida propuesta | Nota | Alcance para la primera beta |
| --- | --- | --- | --- |
| HTTP Custom | `.hc` con estructura abierta y capas reconstruidas | SP-DECODE HTML, sustituir o insertar | HC899 n11 observado sin password/HWID; ampliar después |
| Dark Tunnel | `.dark` abierto, esquema `darktunnel://` observado | Sin banner | JSON abierto y transformaciones SSH/VLESS auditadas; otras variantes no |
| HTTP Injector | `.ehi`, ruta equivalente al E aceptado | SP-DECODE HTML, sustituir o insertar | Formato estándar/AEAD v1 y reglas de hash auditadas; la ruta E requiere una nota válida |
| NPV Tunnel | `.npvs` con NPVO1 abierto | Sin banner | v5 app-key/política vacía observado y NPVO1 de referencia; ampliar passphrase/recipient después |
| HA Tunnel y demás | Ninguna todavía | No aplica | Ocultar exportación compatible hasta validar su exportador |

NPVO1 y el JSON abierto Dark no añaden el cifrado del contenedor protegido;
son las representaciones abiertas observadas. No se promete simultáneamente
un contenedor protegido y un editor abierto si la aplicación los vincula.

El adaptador EHI debe obtener el HMAC mediante material de aplicación auditado
**solo del lado servidor**; el laboratorio depende actualmente del APK fijado.
Hace falta empaquetar ese requisito de forma reproducible en el worker sin
subir APK privados a GitHub ni copiar secretos al cliente. La causa de B/C/D
rechazados sigue abierta; se habilita únicamente la ruta equivalente a E,
validada por importación, editor y banner en la muestra recibida.

## Archivos a modificar cuando se implemente

| Área | Cambio concreto propuesto |
| --- | --- |
| `cloud/web/lib/c3-gateway.mjs` | Admitir y validar la opción QA; propagarla al worker; respetar sesión, cupos, mantenimiento y no-store |
| `cloud/workers/python/server.py`, `engine.py` | Nuevo trabajo opt-in con fuente/credenciales y exportación aislada; límites separados para JSON/artefacto y respuesta total |
| Módulos nuevos de exportación Python | Adaptadores por app, parsers lossless, política única de salida abierta y verificación de retorno; no reescribir lectores funcionales |
| Imagen/Docker y configuración del worker | Dependencias auditadas, plantillas sin conexiones reales y material de aplicación EHI verificable |
| `CloudDecodeClient.kt` | Retornar un DTO de descifrado con capacidad/artefacto opcionales, manteniendo wrappers `String` para llamadores anteriores |
| `MainActivity.kt`, `DecodeSessionViewModel.kt` | Asociar el artefacto al resultado antes de borrar el input; almacén RAM; guardado binario y limpieza en cancelación |
| `SpDecodeApp.kt`, recursos de idiomas | Fila dinámica Exportar para [app] en el diálogo de exportación; copiar intacto; estados de generación/error/expiración |
| `ResultPresentation.kt` | Mantener la presentación separada del archivo nativo; no pasar su JSON al escritor |

El esquema API puede reutilizar la misma ruta HTTPS, por lo que no hace falta
abrir una URL arbitraria ni otro origen en `CloudNativeTransport`. El cambio
del tipo de respuesta exige revisar **todos** los llamadores, incluidas
credenciales, lotes, importaciones remotas e historial; no adjuntar un artefacto
del resultado anterior al actual si se cancela o falla un descifrado nuevo.

## Orden y criterios de aceptación

1. Registrar la aceptación manual NPV y congelar como fixtures privadas los
   archivos aceptados. Paso completado por esta actualización documental.
2. Adaptadores QA que funcionen sin muestras privadas como plantillas de
   despliegue. Separar casos ya validados de ampliaciones password/HWID/recipient.
3. Pruebas sintéticas y reales de apertura autenticada, transformaciones,
   campos desconocidos, contraseñas de conexión intactas, hashes y tags.
4. Contrato gateway/worker: flag apagado, cliente antiguo, credencial incorrecta,
   resultado parcial, variante desconocida, presupuesto de bytes y fallos de
   exportación que no destruyan el descifrado válido.
5. Android: etiquetas por capacidad servidor, guardado binario exacto,
   cancelaciones, rotación, TTL, lote, historial y resultado eliminado.
6. Beta aislada: descifrar en SP-DECODE, exportar, importar en la app original,
   comprobar editor/nota y ausencia de nuevas peticiones de password/HWID/key.
   Para cada variante se exige el resultado manual real; no basta Python.

La propuesta no cambia la rama, no fusiona main y no genera APK/AAB ni
despliega al VPS. El siguiente trabajo de integración debe conservar estos
límites y activar únicamente casos ya verificados.

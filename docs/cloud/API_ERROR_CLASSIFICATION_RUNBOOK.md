# SP-DECODE Cloud — clasificación de errores de descifrado (solo backend)

**Ámbito:** API Node, worker Python y decodificadores Python del servidor.  
**Android:** no se modifica; se reutilizan los códigos que reconoce la APK 1.1.19 (30).  
**Estado:** integrado en la rama del PR #96; **no implica despliegue al VPS**.

## Contrato de resultados

| Código | HTTP | Significado | Incidencia automática |
| --- | ---: | --- | --- |
| `UNSUPPORTED_FORMAT` | 422 | Extensión o formato sin ruta autorizada | No |
| `UNSUPPORTED_VERSION` | 422 | Versión de contenedor no integrada | No |
| `UNSUPPORTED_METHOD` | 422 | Método de protección no implementado | No |
| `UNSUPPORTED_VARIANT` | 422 | Variante no reconocida o posible modificación del archivo; no afirmar cuál sin evidencia | No |
| `NPVS_PROTECTION_UNSUPPORTED` | 422 | Protección NPVS cuya implementación falta | No |
| `PRIVATE_KEY_REQUIRED` | 422 | Archivo firmado destinado a clave privada ECDH no disponible | No |
| `RECIPIENT_MISMATCH` | 422 | Clave pública proporcionada no coincide con destinatarios | No |
| `PASSWORD_REQUIRED` | 422 | Falta contraseña | No |
| `AUTH_FAILED` | 422 | Autenticación de contraseña o datos protegidos fallida | No |
| `INVALID_INPUT` | 400 | Datos malformados, firma NPVS inválida o truncamiento comprobado | No |
| `INVALID_CREDENTIALS` | 400 | Credenciales inválidas para el formato | No |
| `DECODE_FAILED` | 422 | Fallo sin diagnóstico fiable; no adivinar versión ni método | Se conserva diagnóstico |
| `ENGINE_UNAVAILABLE` | 503 | Motor no disponible | Sí |
| `ENGINE_TIMEOUT` | 504 | Tiempo agotado | Sí |

El worker devuelve códigos cerrados y sanitizados; la API no envía trazas,
contraseñas, nombres de archivo ni textos descifrados al sistema de métricas.

## NPVS: los números no identifican por sí solos la clave requerida

En el contenedor compacto NPVS conocido, el **modo** (byte 50 de la
cabecera compacta) significa:

- **`0` — recipient:** apertura mediante ECDH y clave privada del
  destinatario. Una public key permite reconocerlo, pero no descifrarlo.
- **`1` — passphrase:** requiere contraseña y debe diferenciarse entre
  ausencia de contraseña y autenticación fallida.
- **`2` — app-key:** mecanismo de clave de aplicación. **No es un indicador
  de public key ni de clave privada del destinatario**.
  El `keyId` interno es otro campo y no cambia esta distinción.

La versión 5, modo 2/keyId 2, tiene ruta implementada. Si un contenedor
firmado llega a la apertura app-key y no autentica su clave, la API presenta
`UNSUPPORTED_VARIANT`: **puede ser una variante de exportador o un archivo
modificado**. No debe diagnosticarse automáticamente como `PRIVATE_KEY_REQUIRED`,
ni como caída del servidor. La firma invalida del contenedor se informa
separadamente como `INVALID_INPUT`.

Las versiones NPVS no reconocidas se clasifican mediante una cabecera acotada
como `UNSUPPORTED_VERSION`, sin intentar algoritmos de versiones ajenas.
Un encabezado incompleto se considera `INVALID_INPUT`. La identificación
de cabecera no reemplaza las pruebas de firma/autenticación del decodificador.

## Al incorporar un nuevo motor

1. Confirmar contenedor y versión con evidencia reproducible; no adivinar por
   extensión o por un `keyId` numérico aislado.
2. Usar `workerError` JSON únicamente con códigos permitidos y retorno
   controlado del bridge, sin secretos ni excepciones arbitrarias.
3. Conservar la semántica de `AUTH_FAILED` para credenciales incorrectas;
   no convertir autenticaciones fallidas de otro modo en `PRIVATE_KEY_REQUIRED`.
4. Enviar incompatibilidades esperadas como **422**, entrada inválida como
   **400** y caídas de infraestructura como **503/504**.
5. Añadir regresiones de éxito, versión/método incompatible, credencial ausente,
   credencial incorrecta, firma inválida y archivo truncado.
6. Revisar los tests de API/worker antes de desplegar. No modificar Android
   ni aumentar `versionName`/`versionCode` por cambios exclusivos del servidor.

**Importante:** la clasificación es más precisa donde existe evidencia de
framing, firma o método. Los decodificadores históricos que solo retornan
fallo genérico conservan `DECODE_FAILED` hasta instrumentar sus métodos;
no se les asigna una causa inventada.

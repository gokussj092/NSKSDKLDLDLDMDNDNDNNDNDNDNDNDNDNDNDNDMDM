# SP-DECODE 1.1.23 (34): sesiones vinculadas y atestación

Esta rama prepara cambios revisables. No cambia el VPS, DNS, la configuración
del panel ni la pista de Google Play automáticamente.

## Compatibilidad y controles

V1 conserva sus rutas, formatos y controles actuales. Se mantiene disponible por
defecto; `CLOUD_LEGACY_API_ENABLED=false` permite retirarla explícitamente mediante
el proxy de Next.js. Nginx sigue reenviando V1 y publica V2 sólo en el host API.
Los controles de mantenimiento generales y por servicio siguen aplicándose.

La admisión temporal sin Google del panel pertenece a V1. No debilita V2.
`CLOUD_V1_REQUIRE_BOUND_SESSION=true` permite exigir sesiones y pruebas V2 también
en las rutas V1. Ese perfil rechaza los bearer antiguos y debe activarse después
de actualizar los clientes; es independiente de la disponibilidad de las rutas.

## Transporte

Kotlin utiliza IDs; C++ conserva la entrada HTTPS única y TLS de plataforma.
Cada petición firma operación, versión, timestamp, nonce, hash del bearer y hash
de los bytes exactos. Redis consume desafíos y pruebas de un solo uso.
Las claves no se exportan por las APIs del Keystore. El servidor comprueba
además la cadena de atestación de la clave cuando el perfil estricto está activo.
La codificación de direcciones y el hardening ELF son defensa adicional; siguen
siendo analizables y no equivalen a cifrar secretamente todo el programa.

| Operación | Función |
| --- | --- |
| 1 / 2 | Desafío, registro de clave atestada y sesión |
| 4 | Identidad NPVS |
| 5 / 6 | Archivo / texto |
| 7 / 8 / 9 | Importaciones |
| 10 / 11 / 12 | Catálogo / icono / decodificación de servidor |
| 13 / 14 / 15 | Watch / novedades / telemetría |
| 16 | Desafío de integridad para una operación sensible |

El ID 3 continúa rechazado. El contexto autorizado entre V2 y los manejadores
se transmite con WeakMap interno; un cliente no puede crearlo mediante cabeceras.

## Prueba cerrada, hardware y LIAPP

Seguir [HARDWARE_SECURITY.md](HARDWARE_SECURITY.md) para provisionar el verificador
privado, habilitar las etiquetas de Play Console, configurar el número de proyecto
y utilizar el certificado **Play App Signing**. El AAB de prueba cerrada se debe
instalar desde Google Play con una cuenta tester autorizada.

Por defecto V2 requiere clave atestada TEE o StrongBox, dispositivo Android 13+,
Strong Integrity, licencia y actividad reciente evaluada. Las operaciones 4–9 y
12 requieren además un token Standard Integrity con requestHash específico.
El perfil StrongBox es explícito y no cae a TEE. Google, Redis o verificador
indisponibles no activan una aceptación alternativa.

LIAPP puede añadirse al artefacto final siguiendo sus instrucciones oficiales.
Comprobar el AAB protegido y firmado, JNI, Keystore, certificados y Play Integrity
en teléfonos físicos. El repositorio no contiene una licencia ni una integración
de verificación de servidor de LIAPP inventada.

## Validación y límites

Las pruebas cubren sustitución de claves y cuerpos, reenvíos, revocación,
certificados sintéticos firmados, rechazo de sus raíces en producción, políticas
del panel y límites Lua con Redis real en CI. Una prueba de emulador o una suite
aprobada no certifica hardware real ni impide utilizar un teléfono como oráculo.

Probar el flujo completo en la pista cerrada contra el VPS antes de publicar.
Las URLs y nombres de error no son secretos; rotar credenciales sólo cuando
corresponda y nunca incluir claves de Google, worker o backend en el APK.

GET /api/v2/security-policy conserva el aviso informativo solicitado para análisis
automático. No detecta una IA ni sustituye los controles de acceso del servidor.

# SP-DECODE — incidente V2/Android/Cloud/Catálogo: análisis, reparación y contrato para asistentes IA

**Fecha del incidente:** 18 de noviembre de 2026  
**Rama investigada:** `ci/unity-ads-online-qa`  
**Público:** Ghost Developer, Muse, asistentes IA, mantenedores Android, Cloud y VPS.  
**Estado:** **funcionamiento reportado como recuperado por el propietario después del arreglo V2**; pruebas CI relevantes correctas. No equivale a certificar todos los proveedores VPN ni todos los dispositivos.  
**Prioridad:** lectura obligatoria antes de modificar admisión V2, HPKE, Android Online, importaciones, catálogos, límites, worker o instalador.

> **No atribuir sin pruebas todos los errores a Muse ni a los métodos nuevos.** La causa bloqueante comprobada fue un contrato de sesión incompatible entre Android y Cloud. Coincidieron otros defectos de infraestructura y de integración. Este documento separa causas verificadas, síntomas y posibilidades investigadas. Nunca usar como excusa para rebajar seguridad.

## 1. Resumen ejecutivo

En SP-DECODE Online, un usuario podía ver el catálogo local y consultar Firestore, pero al intentar **descifrar un archivo**, **usar una referencia Hex Custom Cloud** o **descargar/descifrar un catálogo de Servidores VPN** recibía el mensaje genérico «No pudimos decodificar este archivo» y posteriormente `INVALID_REQUEST / HTTP 400`. La misma referencia Hex Custom se descargó y descifró con éxito **directamente en el VPS**: por tanto, el descifrador no explicaba por sí solo el fallo de la app.

**Causa raíz del bloqueo común:** la versión Android 1.1.29 (build 44) construía la petición **V2 operación 2 — SESSION** añadiendo `versionName`, `versionCode` y, si estaba disponible, `installerPackage`. En `cloud/web/lib/v2-transport.mjs`, la validación previa del servidor exigía únicamente las claves exactas `challengeId,integrityToken` o `certificateChain,challengeId,integrityToken,publicKey`. El JSON auténtico del cliente se rechazaba **antes de emitir el bearer de sesión**, con `INVALID_REQUEST`/400. Todas las funciones que llaman a `session()` quedaban bloqueadas, incluso si sus decodificadores funcionaban.

**Solución compatible hacia atrás:**
1. El servidor permite únicamente esos **metadatos heredados acotados** en la operación 2, sin utilizarlos jamás como identidad, versión confiable, permiso, autenticación ni atestación.
2. El cliente Android actualizado vuelve a enviar solo `challengeId`, `integrityToken` y, si corresponde, la pareja `publicKey`/`certificateChain`.
3. Continúan las validaciones independientes de **HPKE, PoP ECDSA sobre bytes exactos, challenge de un solo uso, sesión Redis, Play Integrity, Android Keystore/atestación y RASP**.
4. Se añadieron regresiones para la petición cifrada real de Android y para cuerpos maliciosos. La prueba Cloud de extremo a extremo se distingue de una mera prueba de descifrado del worker.
5. El propietario confirmó después: **«Ya, ya funciona»**. Eso confirma recuperación observada, no un ensayo completo de cada una de las aplicaciones del catálogo.

### Síntomas y evidencia que NO deben confundirse

| Observación | Interpretación sustentada |
| --- | --- |
| `[spdecode-hpke] op=1 stage=dispatch status=400 reason=INVALID_REQUEST` | Un bootstrap fue abierto por HPKE y terminó en `INVALID_REQUEST`. El motivo fino de **op 1** no se pudo determinar con aquel log; revisar `CHALLENGE_SCHEMA` / `CHALLENGE_PROOF` / `CHALLENGE_REPLAY` con la instrumentación nueva. |
| `[spdecode-hpke] op=2 stage=dispatch status=400 reason=INVALID_REQUEST` | Petición de sesión V2 inválida tras descifrado HPKE; comparando cliente y servidor se encontró el desajuste exacto de campos. |
| Pantalla «139 aplicaciones disponibles» | Puede reflejar caché local; **no confirma** que se haya descargado una versión nueva ni que la sesión sea válida. |
| Firestore `HTTP 200` + worker `SUCCESS` | Confirma descarga/lectura del documento y apertura en worker. **No** comprueba PoP/HPKE, emisión de sesión o flujo completo Android → API. |
| `BrokenPipeError` del worker | Un cliente/proxy cerró la conexión antes de que llegara el resultado. No demuestra por sí mismo defecto criptográfico. |
| `DecodeFailure("DECODE_FAILED")` en `decode_provider_catalog` | Fallo de **algún catálogo VPN**; no permite concluir que el formato `.hexcm` falló. |
| «HPKE postflight consistent» | Indica que los IDs públicos del **servidor** no cambiaron durante despliegue; **no** prueba por sí solo que coincidan con el pin del APK. |
| `op=1/2 stage=dispatch` | En aquellas solicitudes el servidor **sí superó la apertura HPKE**, así que no era correcto atribuir automáticamente el 400 a clave HPKE diferente. |

## 2. Mapa de arquitectura: dónde puede fallar

```text
Android Online / MainActivity
  -> CloudOnlineReference (detecta proveedor/clave autorizada)
  -> CloudDecodeClient.session()
      op 1 CHALLENGE -> JSON {publicKey}
      op 2 SESSION   -> challengeId, integrityToken, opcional atestación
      validaciones: HPKE -> V2/JSON -> PoP -> challenge Redis -> Play/Hardware
  -> sesión bearer válida (sin atajos)
  -> operación V2 con HPKE, PoP y, si aplica, Standard Integrity + RASP
      op 5  decode/file                (.hexcm local / HXS3 / legado)
      op 7  decode/import/cloud        (HexCustom-* → Firestore)
      op 10 server-vpn/catalog         (catálogo)
      op 12 server-vpn/decode          (descifrar servidor VPN)
      op 13 server-vpn/watch           (solo versión)
  -> Next.js / gateway / proveedor (rutas V1 internas autenticadas)
  -> decoder-worker Python / motor correspondiente
  -> JSON estructurado, diagnóstico acotado, historial / UI Android
```

**Orden de investigación:** 1) versión cliente y commit servidor → 2) op 1/2 → 3) credenciales y token de acción → 4) gateway de la operación afectada → 5) worker y algoritmo. No invertir el orden ni modificar un descifrador cuando ni siquiera se emite una sesión.

### Contrato de SESSION (V2 op 2)

**Cliente vigente recomendado** (representación esquemática, sin token real):

```json
{
  "challengeId": "00000000-0000-0000-0000-000000000000",
  "integrityToken": "TOKEN_VALIDO_DE_PLAY_O_CADENA_VACIA_SI_POLITICA_LO_PERMITE"
}
```

Si `keyAttestationRequired`, se añaden **juntas** `publicKey` y `certificateChain`. El servidor controla si se necesitan.

**Compatibilidad de servidor con APK ya distribuidos:** acepta opcionalmente `versionName` (tres segmentos), `versionCode` (entero acotado) y `installerPackage` (cadena acotada). Son **datos declarados por el cliente, no fiables**. No sustituir con ellos `hardware.versionCode`, `appIntegrity` verificada ni identidad de instalación. Rechazar claves inesperadas, tipos incorrectos, parejas incompletas y replays. Ver `cloud/web/tests/v2-security.test.mjs`.

## 3. Registro de errores, causas y medidas aplicadas

### INC-01 — Bootstrap V2 rechazado con 400: BLOQUEANTE / CAUSA CONFIRMADA

- **Síntoma:** referencia Cloud y catálogos fallaban todos con `INVALID_REQUEST / HTTP 400`; API registraba `op=2 stage=dispatch`.
- **Causa:** `CloudDecodeClient.kt` agregaba metadatos de tester/versión a SESSION; `v2-transport.mjs` empleaba igualdad estricta de conjunto de claves y los rechazaba.
- **Arreglo servidor:** lista permitida cerrada con formatos acotados para compatibilidad; se validan pares de campos y la autenticación continúa descansando en evidencias verificadas.
- **Arreglo Android:** sacar `versionName` / `versionCode` / `installerPackage` de `session()`, conservar metadatos donde su contrato los admite (solicitudes de descifrado).
- **Pruebas:** `cloud/web/tests/v2-security.test.mjs` reproduce Android 1.1.29 en JSON y dentro de HPKE; prueba éxito, campos extra maliciosos, valores inválidos y que las claims usen Play verificado, no el número declarado.
- **Evidencia:** servidor [`e226d929`](../../cloud/web/lib/v2-transport.mjs); pruebas [Actions 44387124077](https://github.com/gokussj092/NSKSDKLDLDLDMDNDNNDNNDNDNDNDNDNDNDMDM/actions/runs/44387124077) — exitosas. Android `6e3546a7` contiene la supresión de extras.
- **Lección:** todo cambio de campos de admisión requiere una prueba **cliente real → servidor** y compatibilidad con APK instalados, incluso cuando el JSON está cifrado correctamente.

**Nota sobre op 1:** hubo 400 también en op 1. No se demostró que compartiera exactamente la misma causa de op 2. Instrumentación segura añadida: `CHALLENGE_SCHEMA`, `CHALLENGE_PROOF`, `CHALLENGE_REPLAY`, `SESSION_SCHEMA` y `UNEXPECTED_ATTESTATION_FIELDS`. No afirmar causalidad no demostrada.

### INC-02 — «RATE_LIMITED» tras horas de inactividad: PRESUPUESTOS MEZCLADOS

- **Síntoma:** usuarios aparentemente inactivos quedaban limitados, incluso al intentar descifrar tras dejar la app abierta.
- **Causa de diseño verificada:** las consultas frecuentes de metadatos, estado y análisis se contabilizaban en presupuesto de descifrado; Nginx tenía un límite por IP compartida (CGNAT) demasiado amplio para el catálogo, y el long-poll se repetía cada 1,5 s.
- **Arreglos:** taxonomía en `cloud/web/lib/v2-routes.mjs`: `metadata` = 10,11,13,14,15,16,17,18,19,20,24,25,29,30; `uploads` = 22,27; `analysisJobs` = 21,23,26,28; `decodeWork` = 4,5,6,7,8,9,12. Presupuestos Redis separados en `bound-auth.mjs` / `device-security.mjs` / `v2-transport.mjs` y rutas V1. Cambio de namespace de contadores antiguos contaminados, manteniendo topes reales para trabajo costoso.
- **Nginx:** generador `cloud/infra/vps/nginx-config.py` asigna la tarifa de descifrado del borde a solicitudes costosas; las consultas informativas no deben gastar presupuesto del descifrador.
- **Poll Android:** `CloudCatalogUpdates.kt` usa retardo de 15 s tras un watch de 12 s; errores no bloquean UI.
- **Cuidado:** nunca sustituir una comprobación de capacidad global por un `429` que inculpe al usuario; las saturaciones globales se informan como capacidad temporal de servicio (`503`), conservando defensa de abuso.
- **Pruebas:** `cloud/web/tests/v2-security.test.mjs`, `device-security.test.mjs`, `capacity-isolation.test.mjs`, `cloud/infra/vps/tests/test_nginx_rate_isolation.py`.
- **Lección:** sesión, metadatos, uploads, análisis y descifrado requieren cuotas distintas; una consulta automática no equivale a trabajo de descifrado.

### INC-03 — Watch del catálogo lleno (64): FALSO 429 / SOBRECONSULTA

- **Causa:** `MAX_OPEN_WATCHES=64` se trataba como fallo para otro usuario aunque el chequeo simple era barato.
- **Arreglo:** `c10-catalog-watch.mjs` entrega versión actual en respuesta `200` con `checkOnly:true` al agotar capacidad de long-polls; no abre un watch adicional. Android respeta pausas y consentimiento.
- **Regla:** avisos de versión o novedades nunca deben desencadenar un descifrado ni una descarga de catálogo sin la acción prevista; no bloquear usuarios anónimos que procesan archivos por no tener cuenta o racha.

### INC-04 — Hex Custom y Hex Tunnel comparten `.hexcm`: RUTAS Y CREDENCIALES

- **Dato de formato:** **Hex Tunnel 1.7.3** usa una envoltura legada y **Hex Custom 10.6.7** usa la nueva envoltura binaria **`HXS3` v3**. **Extensión igual NO implica códec idéntico**. No sobreescribir el lector histórico ni suponer que un proveedor puede interpretar la variante del otro.
- **Detección:** `cloud/workers/python/engine.py` y `hex_custom_bridge.py` seleccionan por **bytes de la cabecera y validación de contenido**, no por el texto de la extensión o el proveedor.
- **Variante HXS3 sin contraseña:** apertura directa.
- **Variante HXS3 con contraseña:** el worker devuelve `PASSWORD_REQUIRED`; la API entrega únicamente en el caso autenticado, con `decode:true` y cabecera HXS3 válida, el fichero cifrado para el diálogo Android; **no vuelve a consultar la referencia remota** para probar la contraseña. Contraseña equivocada → `AUTH_FAILED`; no convertirla en `SERVICE_UNAVAILABLE`.
- **Variante Hex Tunnel antigua:** mantiene su lector, rechazo de credenciales no permitidas y pruebas históricas.
- **Pruebas:** `tests/test_hexcm_shared_routes.py`; `tests/test_hex_tunnel.py`; `cloud/web/tests/c35-import-security.test.mjs`. Incluyen legados, HXS3 protegido/sin protección, contraseña errónea, importación con una descarga y rechazo del handoff para bytes ajenos.
- **Límite de alcance:** no afirmar que se validaron todas las versiones de los dos productos solo porque pasaron los vectores incluidos.

### INC-05 — Firestore funciona, pero Docker no recibe configuración

- **Síntoma en el preflight ANTES del arreglo:** `Firestore document: HTTP 200`; `Actual web -> worker decode: SUCCESS`; **`Compose forwards Hex Custom configuration to web: False`** y **`Running web key matches protected configuration: False`**.
- **Causa:** Compose no propagaba `HEXCUSTOM_FIREBASE_API_KEY` al servicio `web` y/o no había recreado ese servicio con la configuración correspondiente. El hecho de que una prueba independiente reciba una variable no prueba que la aplicación web la tenga.
- **Arreglo:** `cloud/compose.yaml` pasa `HEXCUSTOM_FIREBASE_API_KEY` y `CLOUD_HEXCUSTOM_IMPORT_ENABLED` **solo al contenedor web**, desde `/etc/spdecode/cloud.env`. No a APK, worker, `NEXT_PUBLIC_*` ni código Git.
- **Observación DESPUÉS del despliegue:** las dos comprobaciones pasaron a `True`, proveedor `CONFIGURED` y prueba del worker `SUCCESS`. Fuente Firestore obtuvo **6.958 bytes, HXS3 v3 sin contraseña y JSON de 64 campos de servidor**. Son datos aportados por la prueba en la VPS, no por un test unitario ficticio.
- **Regla:** siempre verificar (1) origen remoto, (2) configuración Compose, (3) variables en el contenedor *en ejecución*, (4) ruta interna web→worker y (5) app Android con sesión V2. Ninguna fase sustituye otra.
- **Seguridad:** el identificador Cloud es un ID de documento con patrón `HexCustom-[A-Za-z0-9]{10}`; las URLs Firestore no vienen del cliente, se construyen mediante host/proyecto/colección permitidos. Nunca aceptar URLs arbitrarias o escribir API keys en documentación.

### INC-06 — «Actualicé la API» pero el motor nuevo no llegó al worker

- **Causa:** `sudo spdecode update api <sha>` construye únicamente el contenedor `web`. Los lectores Python viven en `decoder-worker`.
- **Solución:** cuando cambie `cloud/workers/python/**`, `decoders/Python/apps/**` o dependencias Docker del motor, usar **`sudo spdecode update all <sha>`** (o desplegar explícitamente worker+web de forma compatible), no solamente `api`. Para cambios exclusivos del gateway/web sí sirve `update api`.
- **Prueba de despliegue:** ejecutar `sudo spdecode status`, `sudo spdecode logs worker` y una muestra válida real/sintética del formato correspondiente. La mera presencia del commit en el checkout no prueba que el contenedor se haya recreado.
- **Importante:** `spdecode` lee `/etc/spdecode/cloud.env` con un Compose base y, cuando existe, un override protegido de recursos. Conservar ese override, volúmenes y persistencia.

### INC-07 — `BrokenPipeError` y límites de tiempo del catálogo: ERRORES DE TRANSPORTE DIFERENTES

- **Síntoma:** el worker terminaba y `wfile.write` fallaba con `BrokenPipeError [Errno 32]`. También aparecía `DECODE_FAILED` al procesar un catálogo de proveedor.
- **Corrección:** `cloud/workers/python/server.py` maneja `BrokenPipeError`, `ConnectionResetError` y `ConnectionAbortedError` al responder, sin silenciar errores de lógica; se liberan los semáforos de concurrencia en el flujo normal.
- **Nginx:** `nginx-config.py` amplía el `proxy_read_timeout` **solo para la ruta exacta `/api/v1/server-vpn/decode`** (155 s), no para todo el servidor. Se mantienen límites y tiempos específicos para rutas distintas.
- **Diagnóstico:** el worker registra, si está disponible, `catalog-worker-failure provider=<id> code=DECODE_FAILED`, con identificador acotado y código cerrado; **sin** archivo, enlace privado, contraseña o JSON de salida.
- **No afirmar:** un `BrokenPipe` puede surgir porque la conexión se cerró, pero no prueba por sí solo qué cierre ocurrió ni cuál fue el catálogo afectado.
- **Pruebas:** `cloud/workers/python/test_worker_limits.py` y `cloud/infra/vps/tests/test_nginx_rate_isolation.py`.

### INC-08 — Mensajes genéricos que ocultaban el fallo real

- **Síntoma:** la app decía «archivo inválido» ante una operación que ni alcanzaba el decodificador.
- **Arreglo:** `CloudUserErrors.kt` y `MainActivity.kt` pueden exponer **solo códigos HTTP y enums acotados**, p.ej. `INVALID_REQUEST / HTTP 400`, en las fallas pertinentes. En Cloud se registran operación, etapa y razón sanitizada.
- **Regla:** NUNCA registrar bearer, nonce, firma, cabeceras completas, IP de usuario, Firebase key, clave HPKE privada, texto descifrado o archivo VPN para «diagnóstico rápido». Un rechazo de admisión **no** es un resultado de descifrado.
- **Formato de logs:** `[spdecode-hpke] op=2 stage=admission reason=SESSION_SCHEMA`, `stage=open reason=CLIENT_PIN_MISMATCH`, `stage=dispatch status=400 reason=INVALID_REQUEST` según la etapa. No asumir que cualquier `stage=dispatch` implica que el worker recibió una petición.

### INC-09 — Hipótesis de clave HPKE distinta: INVESTIGADA, NO CAUSA DE ESTE 400

- El actualizador verifica continuidad de IDs públicos del **servidor** antes/después del despliegue; no garantiza compatibilidad contra el pin del APK. Por eso se creó `cloud/infra/vps/hpke-client-pin-audit.py`.
- **No obstante**, los logs reales del incidente fueron `op=1/2 stage=dispatch`: los mensajes **se abrieron con HPKE** antes de devolver 400. Es incorrecto presentar «clave HPKE rota» como causa comprobada de esos dos rechazos.
- Si una futura auditoría devuelve `MISMATCH`, detener el despliegue y revisar el keyring persistente/cliente; **no regenerar, publicar ni sustituir claves a ciegas**.

## 4. Procedimientos obligatorios para Muse y cualquier otra IA

### 4.1 Antes de modificar código

1. **Leer primero** `AGENTS.md` y `analysis/METHOD_EVIDENCE_POLICY.md`. Toda integración de método/versión nueva necesita expediente de evidencia, fuente autorizada, reproducción y pruebas reales; no marcar VERIFIED solo por fixtures sintéticos.
2. Identificar rama de trabajo y HEAD, archivos afectados, dependencias y APKs ya distribuidos. **No cambiar `main` ni otra rama por equivocación**.
3. Escribir un contrato de entrada/salida para **cada operación V2**, incluyendo *campos exactos*, orden si se comprueba el orden, tipos, límites, versionado, firma y casos de error.
4. Determinar qué cambios son **solo servidor** y cuáles requieren APK. Evaluar siempre clientes antiguos vigentes antes de endurecer validaciones.
5. Si una función falla en varias pantallas al mismo tiempo, comprobar **sesión/admisión** antes de tocar scripts de decodificación.
6. Si dos apps comparten extensión, inspeccionar **cabeceras, versiones y muestras**; no asociar un único método a una extensión.
7. Mantener claves, credenciales, perfiles de clientes, hashes sensibles y muestras privadas fuera del repositorio y de respuestas de chat.

### 4.2 Reglas no negociables del protocolo V2

- **Nunca** añadir `versionName`, `versionCode`, `installerPackage`, `accountToken`, `_rasp` u otro campo a `CHALLENGE (1)` o `SESSION (2)` sin actualizar explícitamente **ambos** extremos y sus tests de compatibilidad. La forma cliente actual de `SESSION` es mínima.
- La firma PoP ECDSA se calcula sobre **exactamente los bytes HPKE enviados**, no un JSON reserializado. La verificación del servidor se hace sobre esos mismos bytes; action-integrity también está enlazada al ciphertext final.
- La carga HPKE solo se considera válida tras **autenticación y apertura**. No permitir plaintext como sustituto de respuesta correcta ni «fallback» inseguro por error de transporte.
- No omitir `verifyProof`, `getDel` de challenges, `validBoundClaims`, `verifyAction`, Play Integrity o atestación por «solucionar» HTTP 400/401/403.
- No confiar en metadatos declarados por el cliente para versión, procedencia, roles, permisos o dispositivos. Solo evidencia verificada emite claims de acceso.
- Las operaciones `10,11,13,14,15,16,17,18,19,20,24,25,29,30` son metadatos: no deben consumir el presupuesto de descifrado. Los trabajos caros mantienen presupuestos propios; no subir todos los límites sin pruebas.
- Las solicitudes sin cuenta siguen teniendo su flujo permitido; la lógica de racha/comercio nunca debe exigir cuenta para descifrar donde el contrato admite anonimato.

### 4.3 Al incorporar muchos métodos VPN en lote

- Para cada app: registrar `packageName`, `versionCode`, formato remoto, permiso de acceso, algoritmo/códec, evidencia de muestra, dependencias y proveedor. Diferenciar **catálogo remoto**, **archivo local**, **texto**, **cuentas SSH** y **exportación**; no anunciar compatibilidad no probada.
- Integrar cada método sin reemplazar otros motores, sin scripts destructivos y con código aislado. Aislar credenciales del proveedor en web/worker según necesidad. Mantener los inventarios, switches y las categorías existentes.
- Probar individualmente **catálogo completo** (con campos y conteos), archivo y texto solo cuando existen, con JSON sin truncamientos. Validar errores de credencial/versiones incompatibles sin degradarlos a fallos del servidor.
- Respetar la instrucción del propietario de **incrementar una sola versión del catálogo por lote**, cuando así se solicite. Conservar monotonicidad del número efectivo y decisiones del panel; no activar proveedores no verificados.
- Para 60–80 proveedores, no es suficiente que el índice se muestre: probar ruta real backend de un representante por familia y una muestra por proveedor; entregar matriz de PASS/FAIL/PENDING. No declarar todos comprobados por un solo botón de «Actualizar».
- Preservar iconos e idiomas existentes; si hay cambio de UI, probar flujo real de primer arranque, sesión, catálogo, importación, historial, cierre de ticket y errores.

### 4.4 Matriz mínima de pruebas (obligatoria antes de merge)

| Cambio | Caso positivo | Casos negativos / seguridad |
| --- | --- | --- |
| `op=1/2` | Bootstrap HPKE firmado y sesión para APK actual y anterior | Campo adicional, tipo incorrecto, prueba alterada, replay, IP distinta, certificado no autorizado |
| `op=5` | Archivo de muestra y JSON completo | Truncado, contraseña ausente/errónea, extensión antigua, versión nueva |
| `op=7` | Cloud ID permitido → download → worker; metadata cliente | URL arbitraria, ID inválido, falta de consentimiento, 401, fallo Firestore, no doble descarga |
| `op=10/12` | Listar, seleccionar y descargar/descifrar VPN de prueba | Sesión expirada, `DECODE_FAILED` proveedor, tiempos, formato inválido |
| `op=13` | Watch normal y watch con 64 slots ocupados | No 429 global falso, no bucles 1,5 s, no gastar cuota de descifrado |
| Cuotas | Metadata, uploads, analysis, decode con contadores propios | CGNAT compartida, sobrecarga global sin castigar a individuo, Redis intacto |
| Infraestructura | Compose, Nginx `-t`, web/worker saludables | Variable ausente, rollback, recursos persistentes, proxy timeout específico |
| Release Android | Firma persistente, release/R8, versión compatible, prueba en dispositivo | No usar debug como release, no exigir Play si la política no lo exige |

Pruebas existentes principales:
- `cloud/web/tests/v2-security.test.mjs` — handshake, PoP/HPKE, metadatos y operaciones 5/7/10/12.
- `cloud/web/tests/c35-import-security.test.mjs` — Cloud, referencias autorizadas, Hex Custom y contraseña.
- `tests/test_hexcm_shared_routes.py` / `tests/test_hex_tunnel.py` — códecs de `.hexcm`.
- `cloud/web/tests/device-security.test.mjs` / `capacity-isolation.test.mjs` / `c10-catalog-push.test.mjs`.
- `cloud/infra/vps/tests/test_nginx_rate_isolation.py` / `test_hpke_client_pin_audit.py` / `test_provider_services.py`.
- `cloud/workers/python/test_worker_limits.py` / `tests/test_cloud_c8_user_errors.py`.
- Workflows: `.github/workflows/server-vpn-shared-cache.yml` y `android-unity-ads-online-qa.yml`.

**No relajar asserts de seguridad para que CI quede verde.** Si una prueba vieja tiene una suposición obsoleta (número fijo de rutas o permisos Android), actualizarla para comprobar **la propiedad real**, con justificación, sin deshabilitar la prueba.

## 5. Runbook seguro para diagnosticar en VPS

**No ejecutar indiscriminadamente un «reset total de Redis»**. Puede eliminar sesiones legítimas, revocaciones, datos de comercio, historial, caché y estados de trabajo. El reset excepcional de contadores temporales del incidente fue un remedio puntual y **no fue la causa raíz del HTTP 400**.

### Ver estado sin secretos

```bash
sudo spdecode status
sudo spdecode providers status
sudo nginx -t
sudo python3 /opt/spdecode/repo/cloud/infra/vps/hpke-client-pin-audit.py
```

`CONFIGURED` para Hex Custom significa configuración local reconocida, **no** que el usuario haya autenticado su sesión ni que Firestore conceda cualquier descarga. Revisar aparte el resultado remoto y la prueba dentro del worker.

### Diagnóstico de sesión y catálogo

```bash
sudo spdecode logs api 2>&1 | grep '\[spdecode-hpke\]' | tail -n 30
sudo spdecode logs worker 2>&1 | grep 'catalog-worker-failure' | tail -n 25
```

Interpretación:
- `op=1 stage=admission reason=CHALLENGE_SCHEMA`: validar cuerpo mínimo de op 1.
- `op=1 stage=admission reason=CHALLENGE_PROOF`: firma PoP/bytes/versión/timestamp; no generar firmas falsas.
- `op=2 stage=admission reason=SESSION_SCHEMA`: contrato de campos/tipos de op 2; comparar APK vs servidor **antes** de tocar motores.
- `op=2 stage=dispatch status=400`: V2 abrió HPKE y la lógica de admisión devolvió 400; determinar subtipo por diagnóstico nuevo.
- `stage=open`: investigar cabecera HPKE/keyring/AEAD; no confundir con validación posterior.
- `catalog-worker-failure`: investigar ese proveedor y su muestra. No atribuir a Hex Custom por coincidencia temporal.

### Despliegue seguro

```bash
# Solo gateway/contrato V2/Next.js:
sudo spdecode backup
sudo spdecode update api <SHA_VALIDADO>
sudo spdecode status

# Si cambió worker/decoders/Compose:
sudo spdecode backup
sudo spdecode update all <SHA_VALIDADO>
sudo spdecode status

# Si cambió la generación de rutas Nginx (tras revisar el diff):
sudo spdecode panel sync-routes
sudo nginx -t
```

El CLI `spdecode` almacena el commit anterior para rollback y comprueba la continuidad del keyring de web; esto **no sustituye** pruebas de Android en producción ni auditoría de pin pública. No mezclar `update api` y `update all` sin entender qué contenedor cambia. Conservar `/etc/spdecode/compose.resources.yaml` si existe; **no** destruir volúmenes existentes por warnings de «not created by Docker Compose». Respetar la firma Android persistente; una actualización del servidor **no** instala el APK en el dispositivo.

### Criterios de aceptación de una reparación

1. CI Cloud verde en el commit final; build Docker y Nginx validados.
2. Las operaciones 1/2 dan sesión válida en el APK instalado, sin 400 por esquema.
3. La referencia autorizada y una muestra local se descifran (si el proveedor y la muestra siguen disponibles).
4. Un catálogo VPN de prueba devuelve resultado completo; otros proveedores conservan errores individuales si están pendientes.
5. Ningún watch consume cuotas de descifrado; ninguna consulta de metadatos bloquea procesamiento real.
6. RASP/Play/Hardware/replay siguen denegando solicitudes maliciosas.
7. Evidencia anotada con **commit, workflow, entorno, tipo de prueba y resultado**. Declarar explícitamente pruebas no ejecutadas.
8. Confirmar funcionamiento con el propietario antes de marcar incidencia de producción resuelta.

## 6. Cronología técnica y trazabilidad

| Hito | Referencia | Alcance |
| --- | --- | --- |
| Cuotas y long-poll independientes | `5a9b2d58` | Clasificación metadata/decode, Nginx y Redis, watch, tests |
| Hex Custom/Hex Tunnel y Compose/worker/Nginx | `04068e5d` | Cloud `.hexcm`, Firestore, tiempos, diagnosticar worker y operación de VPS |
| Diagnóstico seguro HPKE, auditoría del pin | `df5f1866` / `e8bedbb5` | Clasificación acotada, pin audit y pruebas |
| Reproducción del contrato Cloud/catalog/file por HPKE | `5b2c8f38` | Operaciones 5/7/10/12 en pruebas de integración |
| Corrección servidor op 2 | `b3656599` y `e226d929` | Campos heredados acotados, pruebas HPKE y diagnóstico bootstrap |
| Corrección Android op 2 | `6e3546a7` | Solicitud SESSION mínima; instalación del nuevo APK es entrega independiente |
| Confirmación de usuario | Conversación del propietario | «Ya, ya funciona» tras la corrección servidor |

Evidencia CI contrastada:
- [Servidor V2: corrección de sesión y suites](https://github.com/gokussj092/NSKSDKLDLDLDMDNDNNDNDNDNDNDNDNDNDNDNDMDM/actions/runs/44387124077) — **success**.
- [Transporte HPKE para operaciones de archivo/import/catálogo](https://github.com/gokussj092/NSKSDKLDLDLDMDNDNNDNDNDNDNDNDNDNDNDNDNDMDM/actions/runs/44380509998) — **success**.
- [Docker/worker y configuración del servidor](https://github.com/gokussj092/NSKSDKLDLDLDMDNDNNDNDNDNDNDNDNDNDNDNDMDM/actions/runs/44365726826) — **success**.
- [Hex Custom y Hex Tunnel en Cloud](https://github.com/gokussj092/NSKSDKLDLDLDMDNDNNDNDNDNDNDNDNDNDNDNDNDNDNDNDMDM/actions/runs/44356487004) — **success**.

**Limitación:** las pruebas CI mayoritariamente usan mocks/red simulada, sin acceso a la VPN del usuario; la prueba real Firestore/worker procede de la salida compartida por el operador. No inferir a partir de estos resultados que todos los proveedores nuevos funcionen. Ver también `AGENTS.md` y la política de evidencia por método.

## 7. Mensaje de traspaso para Muse (copiar como instrucción inicial)

> Trabajas en SP-DECODE, rama `ci/unity-ads-online-qa` o la rama explícitamente asignada. **Lee primero `AGENTS.md` y este incidente completo.** El servidor y Android se comunican por HPKE V2 + PoP; no añadas campos a las operaciones 1/2 ni cambies validadores sin pruebas bidireccionales, compatibilidad con APKs instalados y preservación de Play Integrity/Keystore/Redis. Un fallo simultáneo de Cloud y catálogo suele requerir inspeccionar la sesión 1/2 antes que los decodificadores. Catálogos informativos NO consumen cuotas de decode. Hex Custom HXS3 y Hex Tunnel clásico comparten `.hexcm`, pero no el mismo lector. Secrets solo en entorno servidor; actualiza el worker cuando cambies motores, nunca solo web. Con cada método nuevo aporta expediente `analysis/`, casos reales/sintéticos diferenciados, matriz PASS/FAIL/PENDING y resultados CI; no inventes funcionalidad o declaraciones VERIFIED. Conserva recursos, volúmenes, firma Android y switches/versión monotónica del catálogo. Nunca publiques claves ni desactives seguridad por un error HTTP. 

## 8. Documentos relacionados

- [Instrucciones para asistentes](../../AGENTS.md).
- [Política de expediente por método](../../analysis/METHOD_EVIDENCE_POLICY.md).
- [Migración V2 y garantías de seguridad](V2_SECURITY_MIGRATION.md).
- [Clasificación de errores del worker](API_ERROR_CLASSIFICATION_RUNBOOK.md).
- [Guía del catálogo Server VPN](C8_SERVER_VPN_CATALOG.md).
- [Persistencia de recursos del VPS](PERSISTENT_VPS_RESOURCES_2026_11_15.md).
- [Expediente Hex Tunnel](../../decoders/Python/apps/Hex_Tunnel/README.md).

**Regla final para cualquier IA:** cada cambio debe explicar **qué contrato afecta, qué versión anterior podría romper, qué prueba real lo demuestra, cómo se despliega y cómo se revierte**. Un commit verde sin prueba de sesión Android → API no basta para declarar una integración Cloud terminada.

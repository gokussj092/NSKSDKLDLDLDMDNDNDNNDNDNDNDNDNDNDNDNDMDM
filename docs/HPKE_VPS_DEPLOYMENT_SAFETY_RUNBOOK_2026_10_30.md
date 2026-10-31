# SP-DECODE — Procedimiento de despliegue seguro y prevención de regresiones HPKE

**Fecha:** 2026-10-30 · **Rama de documentación:** feat/post-native-security · **Estado:** documentación operativa; no es una implementación automatizada.

## 1. Propósito

Evitar que una actualización de GitHub a la VPS deje el frontend de Next.js saludable, pero inutilice el descifrado desde Android por pérdida de configuración, incompatibilidad de claves HPKE o cambios de política de integridad. El endpoint de vida no es una prueba de funcionamiento de descifrado. No se deben confundir dos hitos: **deploy correcto de contenedores** y **funcionamiento Android → HPKE → V2/Play → worker → respuesta autenticada**.

### Incidente confirmado

- Repositorio privado Goku: gokussj092/NSKSDKLDLDLDMDNDNNDNDNDNDNDNDNDNDNDNDMDM. Se integró security/hpke-native-cpp-migration en main mediante **PR #108**, commit **ffcfb8887174eeba09c9dbd90e493a51b100ef90**.
- APK/AAB de pruebas firmados **1.1.24, build 37**: GitHub Actions **41156789776**. El Gradle de main conserva versionName **1.1.24** y versionCode **35**; el code 37 se sustituyó únicamente durante CI.
- Tras ejecutar **spdecode update all main**, el usuario observó aplicación: “el servidor se encuentra fuera de servicio” al intentar descifrar un archivo.
- En ese momento, VPS: web/worker/Redis healthy, /api/health/live respondió **HTTP 200**, Next.js **16.4.3**, React/React DOM **19.3.1**, Python msgpack **1.2.4** y requests **2.33.1**. La salud general y los parches eran reales, pero insuficientes.
- Diagnóstico de proceso en **spdecode-web-1**: CLOUD_API_ENABLED=true; **CLOUD_V2_HPKE_ENABLED=false**, **CLOUD_V2_HPKE_KEYRING ausente**, CLOUD_V2_HPKE_ONLY=false, CLOUD_FORCE_MAINTENANCE=false, CLOUD_ACTION_INTEGRITY_REQUIRED=true, proyecto Play configurado.
- Redis no mostró activación de mantenimiento general; el archivo v2-availability.json indicó **enabled=true**.
- El par HPKE del VPS nunca se había perdido: archivo protegido **/etc/spdecode/keys/v2-hpke-keyring.json**, con clave privada presente y KID público **896f195624217d42**.
- El pin público incluido en **spdecode_transport.cpp**, biblioteca **libv7q3.so**, coincide con ese KID; NO hace falta generar claves nuevas o recompilar APK para restaurar este par.
- Se recuperó el entorno del contenedor mediante una copia de seguridad de cloud.env, inyección protegida del JSON existente en CLOUD_V2_HPKE_KEYRING, CLOUD_V2_HPKE_ENABLED=true, CLOUD_V2_HPKE_ONLY=false y recreación **solo del servicio web**, sin modificar fuentes ni rotar claves.
- Comprobación posterior del usuario: HPKE activado **true**, KID compatible **true**, HPKE_ONLY **false**; web/worker/Redis saludables y GET /api/health/live OK. **Aún no consta, en este chat, una prueba Android real posterior de descifrado exitosa.** No declarar la recuperación de E2E como validada hasta realizarla.

**Causa inmediata confirmada:** el contenedor recién desplegado carecía del interruptor y del keyring HPKE, por lo que el endpoint V2 rechaza solicitudes cifradas con HTTP **503 / SERVICE_UNAVAILABLE**. **Causa raíz operativa a evitar:** la infraestructura trata los valores HPKE como opcionales, con defaults desactivados en cloud/compose.yaml, y el actualizador actual sólo verifica el health de Next.js; no aplica un contrato pre/post-despliegue de claves compatibles. No afirmar, sin análisis histórico adicional, el mecanismo exacto por el que la configuración dejó de propagarse.

## 2. Componentes y límites de confianza

| Pieza | Ubicación / requisito |
| --- | --- |
| Código de servidor | /opt/spdecode/repo, desplegado por spdecode update api/web/worker/all |
| Servicio Compose | cloud/compose.yaml; único servicio web Next.js para sitio, API y panel |
| Configuración de producción | /etc/spdecode/cloud.env (0600, sensible; nunca subir a Git) |
| Clave privada HPKE persistente | /etc/spdecode/keys/v2-hpke-keyring.json (0600, fuera del repo) |
| Variable consumida por Node | CLOUD_V2_HPKE_KEYRING: JSON del keyring, no ruta de archivo |
| Interruptor de admisión | CLOUD_V2_HPKE_ENABLED=true |
| Compatibilidad V2 anterior | CLOUD_V2_HPKE_ONLY=false mientras convivan versiones previas |
| Pin público APK | android/app/src/main/cpp/spdecode_transport.cpp: pin de X25519 ofuscado en dos partes; KID conocido |
| Lógica de recepción | cloud/web/lib/v2-hpke.mjs y cloud/web/lib/v2-transport.mjs |
| Actualizador VPS | cloud/infra/vps/spdecodectl; spdecode update all actualiza código y reconstruye imágenes |
| Acceso a KeyStore/Play | Reglas de attestation, Play Integrity, PoP y sesión independientes de HPKE |

HPKE base mode no demuestra por sí mismo la identidad de la aplicación: Play Integrity, hardware attestation, firma de solicitud y autorización del backend siguen siendo obligatorias según la política vigente. El transporte anterior no debe usarse como fallback silencioso de una sesión ya comprometida a HPKE.

## 3. Checklist obligatorio ANTES de desplegar

1. Identificar **qué versión de APK, qué commit y qué pin KID** se van a probar. Una build 37 firmada en Actions es candidata de pruebas, no una aprobación Play ni un cambio de versión fuente.
2. Verificar el **KID del receptor** contra el pin público de la APK. Si no coincide, **detener el despliegue** y preparar una rotación coordinada; no generar un par nuevo para “arreglar” la comprobación.
3. Verificar existencia, permisos y respaldo cifrado **fuera del VPS** del keyring; jamás copiarlo dentro de Android, de Git o de logs. Respaldar también /etc/spdecode/cloud.env, /etc/spdecode/install.conf, configuración Nginx y metadatos/versiones de contenedores.
4. Comprobar que cloud.env contiene el opt-in HPKE requerido, que su JSON puede cargarse sin errores y que **CLOUD_V2_HPKE_ONLY** mantiene la política de coexistencia acordada.
5. Comprobar que el Git working tree del VPS está limpio; el actualizador usa fetch y reset --hard. Nunca usar reset sobre cambios no respaldados. No desplegar la rama futura de documentación como sustituto de main.
6. Revisar **CLOUD_FORCE_MAINTENANCE**, política V2 durable, Play Integrity y certificados; los flags sensibles NO se alteran por un simple parche de Next.js.
7. Revisar CI y pruebas de interop, así como su relación con la revisión desplegada: una compilación firmada exitosa **no reemplaza** test de dispositivo ni test end-to-end.
8. Reservar plan de rollback (commit previo, copia cloud.env, keyring, rollback Compose y métricas). Ningún paso de diagnóstico debe imprimir el JSON privado.

El comando **spdecode backup** respalda cloud.env, install.conf y SHA de código, **pero NO respalda automáticamente el archivo separado /etc/spdecode/keys/v2-hpke-keyring.json**. Extender el backup seguro o documentar un procedimiento de copia cifrada independiente; no almacenar duplicados legibles.

## 4. Comprobación segura de SOLO LECTURA

Primero inspeccionar el archivo **sin imprimir secreto**:

~~~bash
sudo test -s /etc/spdecode/keys/v2-hpke-keyring.json && echo "Keyring HPKE presente"
sudo stat -c '%a %n' /etc/spdecode/keys/v2-hpke-keyring.json
sudo spdecode status
~~~

Tras deploy o recreación, comprobar la configuración **del proceso real**:

~~~bash
sudo docker exec spdecode-web-1 node --input-type=module -e '
import { hpkeKeyIds } from "/app/lib/v2-hpke.mjs";
const env=process.env;
const enabled=env.CLOUD_V2_HPKE_ENABLED==="true";
const only=env.CLOUD_V2_HPKE_ONLY==="true";
const ids=hpkeKeyIds();
const match=ids.includes("896f195624217d42");
console.log("HPKE habilitado:",enabled);
console.log("KID compatible:",match);
console.log("HPKE_ONLY:",only);
if(!enabled || !match)process.exit(1);
'
~~~

La función hpkeKeyIds valida el JSON, deriva el identificador y comprueba las parejas de claves; imprimir solamente estado booleano y KID público. Si falla, **detener pruebas de descifrado y no reportar despliegue listo**. El KID es el del APK firmado de este incidente: cambiarlo únicamente mediante revisión explícita de rotación.

Comprobar además el mantenimiento general y la política V2 sin mostrar credenciales:

~~~bash
sudo docker exec spdecode-redis-1 redis-cli GET spc6:maintenance
sudo docker exec spdecode-web-1 cat /app/provider-control/v2-availability.json
curl -fsS --max-time 15 https://api.spdecode.xyz/api/health/live
~~~

**No** usar docker inspect, docker compose config, cat cloud.env ni echo CLOUD_V2_HPKE_KEYRING para compartir diagnósticos: podrían exponer la clave privada en el chat o logs.

## 5. Procedimiento de actualización y verificación posterior

**Orden recomendado:**
1. Respaldo seguro del estado anterior, incluido keyring fuera de Git y volumen persistente. Registrar commit/tag.
2. Preflight criptográfico: existencia de keyring, coincidencia KID, flags y disponibilidad de Play/Redis/worker.
3. Actualizar código y reconstruir imágenes mediante el operador autorizado (**spdecode update all main** solo si la revisión fue aprobada).
4. **Postflight de HPKE en el contenedor recreado** con el comando del apartado 4. Si se pierde una variable, **no regenerar la clave**: restaurar configuración protegida y recrear solamente web.
5. Comprobar estado HTTP y proceso worker, versiones instaladas (Next/React/msgpack/requests), Redis, política V2 y ausencia de mantenimiento.
6. Ejecutar **smoke E2E desde un Android físico**: abrir app firmada, completar sesión/Play/attestation, descifrar un archivo de fixture no sensible, recibir y autenticar respuesta HPKE; repetir tras reinicio del contenedor. Probar un cliente anterior si la convivencia sigue habilitada.
7. Sólo entonces registrar “despliegue funcional” con timestamp, SHA, build de APK, KID público y resultados (sin contenido de archivos, bearer, claves ni tokens).

**Distinciones de error:**

| Síntoma | Posible condición | Primera comprobación |
| --- | --- | --- |
| /api/health/live = 200 pero app = servicio fuera de línea | HPKE deshabilitado; policy/config 503 | CLOUD_V2_HPKE_ENABLED, keyring, v2 availability |
| HPKE activado pero sesión no establecida | Play Integrity / atestación / cuenta o política | Veredicto servidor por código de error, no valores secretos |
| 400 al abrir envelope | Key ID, tag, framing, versión u operación incorrecta | KID y fixtures entre APK y Node |
| 401/403 | Firma PoP, sesión, Play, action integrity | Estado y código tipado; no aflojar políticas |
| 429/504 | Rate limit / timeout | Contadores y salud worker |
| /health/live = 200 | Sólo prueba web/HTTP básica | NO concluye que HPKE, sesión o descifrado funcionen |

## 6. Prevención en código e infraestructura: PENDIENTE, NO IMPLEMENTADA

Propuesta futura para la rama feat/post-native-security (revisión y PR separados):
- **Fail-fast condicional:** si release espera HPKE para la build activa, rechazar deploy si faltan ENABLED=true, JSON válido o el KID del binario no aparece en el keyring. Comprobar antes y después de recrear el servicio web.
- **Preflight sin revelar secretos:** lectura segura de archivos externos, permiso 0600/0700, keyring con una a tres entradas, verificación X25519 y compatibilidad con todos los KID activos. No imprimir JSON ni valores de ENV.
- **Readiness distinto de liveness:** un chequeo privado/autenticado o comando CLI que verifique configuración de transporte, Redis y policy sin aceptar tráfico artificial ni exponer material de sesión; conservar /health/live como liveness.
- **Smoke de protocolo cifrado:** cliente sintético controlado o dispositivo tester que complete HPKE, respuesta cifrada y rechazo replay/tampering. Registrar sólo resultados no sensibles.
- **Ciclo de secretos:** migrar, si se justifica, de keyring serializado como env de contenedor a mecanismo seguro de secret/file mount, actualizando lector y Compose juntos. No asumir que un archivo en /etc/spdecode/keys se monta solo.
- **Rollback integral:** el script debe recuperar la configuración válida y el commit anterior sin destruir volúmenes provider-control/notice-feed ni las claves privadas; evitar imprimir secretos en logs.
- **CI de upgrade:** simulación de despliegue con Compose partiendo de una configuración HPKE previa, pruebas de falta de keyring, KID incorrecto, mantenimiento y servicios sanos pero API fallida.
- **Versionado:** asociación explícita commit ↔ APK build ↔ key IDs admitidos ↔ política Play, más despliegue canario antes de producción.
- **Auditabilidad:** verificar paquetes y dependencias transitivas reales, no únicamente las versiones declaradas. La fuente del incidente no era Next.js 16.4.3 ni msgpack 1.2.4.

## 6A. Implementación de no regresión en la rama post-native (sin despliegue)

**Estado: implementado en código y probado con estado sintético; NO desplegado en VPS.**

Se agregó una comprobación acotada en `cloud/infra/vps/spdecodectl`, dentro de `spdecode update api|web|panel|all`. Antes de `sync_ref`:

- Consulta dentro del contenedor web los KID públicos derivados con `hpkeKeyIds()`, o `OFF` si HPKE estaba desactivado, sin imprimir variables ni el keyring.
- Si el contenedor tenía HPKE activo, exige que `cloud.env` protegido conserve `CLOUD_V2_HPKE_ENABLED=true` y una entrada no vacía `CLOUD_V2_HPKE_KEYRING`. No rota ni fabrica claves.
- Si el archivo protegido dice que HPKE debe estar activo pero el contenedor informa `OFF`, impide la actualización.
- Después de recrear web y superar HTTP liveness, exige conservar **exactamente el mismo conjunto de KID** públicos. Si se pierden o cambian, señala fallo, restaura el commit anterior y ejecuta el procedimiento existente de reconstrucción/rollback. Una rotación deliberada deberá tener procedimiento separado.

Las pruebas `tests/test_r0_hpke_update_guard.py` simulan flags faltantes, keyring ausente, lectura no disponible, regresión a `OFF`, cambio de KID y casos válidos; nunca invocan Docker real ni cargan la clave privada. La ejecución host CI está registrada en el documento R0.

**Limitaciones antes de producción:** este guard sólo preserva un HPKE que ya estaba operativo. No sustituye la declaración obligatoria de KID para un VPS recién instalado, ni valida `Play Integrity`, sesión, respuesta HPKE o worker. Sólo cubre `update` de web/API/panel/all; los caminos de `restart`, instalador y cambios manuales de configuración aún requieren tratamiento. El rollback actual revierte código y reconstruye contenedores, pero no puede restaurar mágicamente una configuración `cloud.env` alterada externamente. Sigue siendo indispensable respaldo del keyring fuera de Git y validación E2E de Android físico. **No promover este control como garantía integral de deploy hasta ejecutar simulaciones Docker y rollback real en staging.**

## 7. Estado de trabajos/CI y criterios de cierre

- Merge completado: PR #108, SHA ffcfb888.
- Pruebas específicas de interop HPKE/nativo y build Android: Actions **41154662597**, **41154662634** y firmada **41156789776**, success.
- En el PR global se detectaron checks heredados fallidos (baseline de UI/UX sin rebaseline, expectativas antiguas de nombre/símbolos JNI y job Node sin instalar @hpke/core). Se deben reparar/verificar antes de una promoción sin reservas; no declarar todo CI en verde.
- El test real posterior de descifrado desde Build 37 **aún es PENDIENTE de confirmar**.
- La prevención se considerará completa solo si un despliegue con HPKE ausente **falla antes de exponer la API** y un despliegue correcto supera health + prueba criptográfica + E2E Android, con rollback probado.

## 8. Documentos relacionados

- docs/V2_HPKE_TRANSPORT.md
- docs/NATIVE_HPKE_CPP_MIGRATION.md
- docs/SECURITY_CXX_BOUNDARY_AND_DEPENDENCIES_2026_10_30.md
- docs/ANDROID_RASP_ANTI_TAMPER_ROADMAP_2026_10_30.md

**No generar ni rotar claves como medida de diagnóstico. No quitar Play Integrity. No fusionar automáticamente esta rama a main.**

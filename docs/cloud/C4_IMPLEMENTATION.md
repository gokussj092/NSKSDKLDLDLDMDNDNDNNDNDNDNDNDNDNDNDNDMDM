# C4 — SP-DECODE Cloud: Android + C++ JNI

**Rama:** `feat/cloud-c4-android-jni`, basada en C3.5 (#89), que sigue dependiendo de #88 → #87 → #86.

## C4.1 — Transporte nativo con el nombre exacto

Se incorpora **`libspdecode.so`** mediante NDK/CMake en `android/app/src/main/cpp/`.

El código C++ controla los endpoints públicos permitidos, construye los POST HTTPS, maneja timeouts, TLS de Android (certificado y nombre verificados por `HttpsURLConnection`), desactiva redirecciones, limita el tamaño de solicitudes/respuestas y retorna el cuerpo JSON y estado HTTP a Kotlin. La implementación invoca la API de red de Android desde JNI **sin introducir claves maestras ni algoritmos de descifrado dentro del binario**.

La biblioteca jamás recibe URLs arbitrarias de HTTP Injector ni de NUR; son operaciones del **servidor C3.5**. El origen público de la API se valida al compilar con `SPDECODE_CLOUD_API_BASE_URL` y se **incrusta como constante en C++** de `libspdecode.so` mediante CMake; no se pasa como parámetro desde Kotlin. Es una configuración pública, no un secreto. Las rutas nativas permitidas son challenge, session, decode/file, decode/text, decode/import/cloud y decode/import/catalog/remote. No existen ni rutas de claves internas ni acceso directo al worker.

## C4.2 — Play Integrity y sesiones temporales

El adaptador `CloudDecodeClient.kt` usa el SDK oficial **Play Integrity clásico**: llama a `/api/v1/session/challenge`, solicita el veredicto con el nonce generado por el backend y lo entrega a `/api/v1/session`. La verificación de firmas/veredictos ocurre **exclusivamente en el backend** (C3). Kotlin conserva en memoria el token bearer del backend hasta un máximo de cinco minutos, con margen antes de reutilizarlo. Ningún token o archivo se registra en logs.

Un dispositivo fuera de las condiciones de Play Console/Play Integrity no podrá completar las peticiones Cloud; **no se omite la validación ni se activa un fallback local**. La prueba de APK de C4 valida la compilación, pero no representa un descifrado real certificado.

## C4.3 — Sustitución de operaciones existentes, sin cambio visual

Solo se modifica la orquestación interna de `MainActivity.kt` (archivo excluido expresamente del candado de hash visual C0). Los nueve archivos UI/UX congelados permanecen **byte a byte idénticos**:

| Operación en pantalla existente | En build Cloud |
| --- | --- |
| Seleccionar 1–30 archivos por SAF | Android detecta extensión; manda bytes y extensión exacta por `/api/v1/decode/file`, mantiene progreso, cancelación visual e historial |
| Archivos `.hc` protegidos | Usa el mismo diálogo existente. Contraseña/HWID se transfieren por HTTPS en la petición; ni se escriben a archivos ni se envían a motores ajenos |
| Texto pegado | Usa la clasificación local existente únicamente para el nombre de la tarjeta. El descifrado corre por `/api/v1/decode/text` |
| HTTP Injector Cloud | Conserva panel original; importa mediante `/api/v1/decode/import/cloud` con `consent:true` |
| NUR Server VPN | Conserva el botón original; importa mediante `/api/v1/decode/import/catalog/remote` con `consent:true` |

`CloudDecodeClient` **no** entrega resultados parciales, vacíos o sin `rawText`. Mantiene el texto completo de respuesta para el árbol JSON, copiar/exportar, favoritos e historial. En errores de red/Play/decodificador conserva los estados de error de la UI anterior, sin sustituirlos por respuestas ficticias.

**Fase C5 pendiente:** todavía se compilan los motores y materiales locales anteriores para los builds de compatibilidad/regresión. No es correcto afirmar que la APK actual tenga secretos eliminados. C5 hará el desmontaje de los motores/assets del cliente, condicionado a equivalencia y validación de todos los formatos.

## C4.4 — Activación controlada de la ruta Cloud

La app compila en modo compatible legado **cuando falta** `SPDECODE_CLOUD_API_BASE_URL`; esto preserva las pruebas Android existentes durante la migración. Un build habilitado con una URL HTTPS válida **siempre usa Cloud** y **no** recurre a descifrado local ante fallas de red.

```bash
cd android
SPDECODE_CLOUD_API_BASE_URL=https://api.example.com gradle :app:assembleDebug
```

No se ha desplegado esa dirección de ejemplo. Antes de firmar una versión de producción Cloud se requieren: dominio API propio y HTTPS, backend habilitado con todos los secretos únicamente en servidor, Redis, veredictos Play Integrity reales, consentimiento y avisos de privacidad, pruebas de muestras autorizadas y C5 finalizado. La bandera `SPDECODE_CLOUD_RELEASE=true` evita construir una release identificada como Cloud sin un origen API configurado.

La CLI de GitHub Actions `.github/workflows/cloud-c4.yml` compila un APK debug de comprobación, verifica los formatos y candado visual, comprueba que el archivo real `libspdecode.so` exista en el ZIP de APK y que `libspdecode_cloud.so` no exista. Este workflow **no distribuye** la APK a usuarios ni modifica la versión pública.

## C4.5 — Límites y riesgos pendientes

- API de Play Integrity real exige Play Console y verificación server-side; las pruebas CI solo usan compilación con host ficticio.
- Una sesión de red podría seguir activa hasta timeout del socket tras cancelar la tarea; la pantalla no debe guardar su resultado cuando cambie la generación. Cancelación activa del socket queda para pruebas de integración.
- El almacenamiento local del historial contiene resultados descifrados; su política de retención, consentimiento de envío y privacidad deben revisarse antes de Play Store.
- El código Kotlin/NDK aún está dentro de una APK con algoritmos locales hasta C5; no confundir compilación nativa con eliminación de secretos.
- Es obligatorio revisar paridad de formato de salida (C7), HCCFG password/HWID, 240 rutas, texto G, HTTP Injector Cloud y NUR; todas las variantes reales deben ser comprobadas con muestras lícitas.
- El flujo `GET /api/v1/capabilities` puede presentar motores registrados que no son versiones certificadas; **no** usarlo como criterio de lanzamiento.

**No hubo cambio en los nueve archivos visuales fijados por C0, ni en el bot. No fusionar con main / publicar APK de producción hasta completar controles C4/C5.**

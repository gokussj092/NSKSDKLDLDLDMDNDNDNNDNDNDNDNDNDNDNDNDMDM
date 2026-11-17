# APK original para Muse/Yamada, sin sesión de usuario

## Corrección

La ruta `…/[jobId]/download` entrega el **resultado** `result.zip`, cuando el
trabajo termina, con las reglas de acceso de su propietario. No sirve el APK
subido. Esa ruta y sus permisos se conservan.

Se añade una entrega de **entrada** independiente, de solo lectura, utilizando
el token de servicio que ya emplea el bot para events/complete/fail. No usa
Google, Better Auth, cookies del panel ni la sesión del dueño. También permite
enlaces temporales limitados a un archivo para clientes que no pueden enviar
cabeceras de autenticación.

## Despliegue

En la VPS, actualizar únicamente el servicio web/API:

```sh
spdecode update web ci/unity-ads-online-qa
```

Esta corrección sí es del servidor; no requiere otra APK ni migración SQL.
Se reutilizan `SPDECODE_APP_ANALYSIS_BOT_TOKEN` y
`SPDECODE_APP_ANALYSIS_DOWNLOAD_SECRET`, sin crear otra clave. El análisis,
créditos, soporte, webhook y vigilante de 15 minutos no cambian.

Las rutas nuevas se consultan en **`https://api.spdecode.xyz`** (o en
`CLOUD_API_PUBLIC_ORIGIN` si el despliegue lo personaliza). El proxy existente
del host API ya permite `/api/v2/app-analysis/`. El host público
`spdecode.xyz` mantiene su restricción V2: no hay que abrirlo ni cambiar Nginx.

## API de servicio

| Petición | Acceso y respuesta |
| --- | --- |
| `GET /api/v2/app-analysis/queue` | Token del bot; hasta 50 trabajos pendientes, en análisis o en revisión, ordenados por creación; incluye enlaces de entrada. |
| `GET /api/v2/app-analysis/{jobId}/input-link` | Token del bot; genera/renueva el enlace de un trabajo existente. |
| `GET /api/v2/app-analysis/{jobId}/input` | Token del bot; descarga directa del original, incluso si aún no hay resultado. |
| `GET` o `HEAD` sobre `inputDownloadUrl` | **Sin sesión, cookies ni Authorization**; el enlace temporal es la autorización. |

Las tres primeras peticiones admiten la cabecera existente
`Authorization: Bearer <SPDECODE_APP_ANALYSIS_BOT_TOKEN>` o
`X-SP-Analysis-Bot-Token`. La sesión de soporte no reemplaza ese token.
No se debe poner el token permanente en una URL, en el repositorio ni en el chat.

Cada entrada contiene `jobId`, `filename`, `packageName`, `appName`, `bytes`,
`sha256`, `inputDownloadUrl` y `expiresAt`. No incluye cuenta, sesión, token del
bot, clave de firma ni rutas internas. Para un trabajo que ya estaba en cola
antes del despliegue basta solicitar la cola o su `input-link`; no hay que
volver a subirlo ni emitir otro evento.

### Obtener los enlaces desde la VPS sin mostrar el token

El contenedor ya tiene las variables de servicio. Este comando solo imprime
metadatos y enlaces temporales para compartir con Muse:

```sh
docker exec spdecode-web-1 node --input-type=module -e '
const response=await fetch("http://127.0.0.1:3000/api/v2/app-analysis/queue",{
  headers:{authorization:"Bearer "+process.env.SPDECODE_APP_ANALYSIS_BOT_TOKEN}
});
if(!response.ok){console.error("HTTP "+response.status,await response.text());process.exit(1);}
console.log(JSON.stringify(await response.json(),null,2));
'
```

Muse puede descargar la URL `inputDownloadUrl` con su cliente HTTP habitual,
sin iniciar sesión. El enlace dura **15 minutos**, o menos si vence la retención
del trabajo. Se renueva con `input-link` o consultando la cola con el token.
El archivo mantiene su nombre `.apk`/`.apks`; no es el ZIP de resultados.
Comparar el SHA-256 recibido con `sha256` o con la cabecera `X-Input-SHA256`.

## Límites y comprobaciones

- Solo entradas completas que pasaron a cola/análisis/revisión, o terminaron
  correctamente. Entradas en subida, rechazadas, fallidas o caducadas no se sirven.
- HMAC-SHA256 separado por propósito, ligado a job, propietario, SHA, tamaño y
  caducidad. Una firma de resultados no abre una entrada ni otra cuenta/trabajo.
- La cola detallada requiere token; `/api/app-analysis/queue-status` sigue
  siendo el contador público original y no entrega IDs ni enlaces.
- Lectura por stream, sin cargar los 150 MB en RAM. HEAD y rangos de bytes
  permiten verificar y reanudar una descarga. Rangos inválidos devuelven 416.
- Archivo regular de tamaño esperado, UUID validado y `O_NOFOLLOW` al abrir.
  Los enlaces no se indexan ni se almacenan en caché. No se inicia el análisis
  ni se toca el saldo, reserva, estado o eventos al leer o generar un enlace.
- Configuración de firma ausente: `input-link` devuelve 503; el bot aún puede
  usar descarga directa si su token está configurado. Anónimo sin enlace válido
  recibe 401. Archivo ausente/truncado devuelve 503 para revisar el volumen.

Pruebas reproducibles, desde la raíz del repositorio con dependencias web:

```sh
node --test cloud/web/tests/app-analysis-input.test.mjs \
  cloud/web/tests/app-analysis.test.mjs \
  cloud/web/tests/app-analysis-queue-status.test.mjs
npm run build --prefix cloud/web
```

Las pruebas emplean PostgreSQL embebido y archivos sintéticos, nunca una APK
privada del propietario. Comprueban permisos, descarga exacta sin login,
expiración, firmas y archivos alterados, rangos, aislamiento y ausencia de cobros.
Resultado local: **40/40** pruebas y compilación Next.js **16.4.3** correctas,
con las tres rutas nuevas incluidas en el build. Las políticas V1/V2 del
servidor siguen siendo obligatorias; no se generan ni sustituyen en este cambio.
La descarga real de DeepTune-VPN queda por comprobar después de desplegar en
la VPS; no se ejecuta aquí su análisis ni se cambia el soporte de Muse.

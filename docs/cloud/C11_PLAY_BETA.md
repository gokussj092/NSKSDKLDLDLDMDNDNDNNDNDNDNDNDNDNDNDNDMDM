# SP-DECODE — publicación cerrada de Google Play y APK beta

Operador/editor: **Ghost Nexora Studio**. Nombre comercial del desarrollador; no altera el
paquete **`com.ghostdeveloper.spdecode`** ni el nombre visible SP-DECODE.
Rama: `feat/austroplus-vpn-13-0-1-decoders`; PR #96 abierto y sin fusionar.

## Archivos
El workflow `.github/workflows/play-beta-artifacts.yml` compila **dos formatos a partir
del mismo código, versión 1.1.4, versionCode 25, y Android 16 (targetSdk 36)**:
- `SP-DECODE-v1.1.4-play-closed-test-signed.aab`: subir al track **Prueba cerrada**
  en Google Play Console.
- `SP-DECODE-v1.1.4-beta-external-signed.apk`: distribución fuera de Play.
- `SHA256SUMS.txt` y `SIGNATURE_VERIFICATION.txt`.

Los dos usan **la clave permanente** de GitHub Secrets `SPDECODE_SIGNING_*`, sin
generar otra ni almacenar contraseñas en el repositorio. El AAB se firma para subir a
Play; Google Play firma los APK que entrega a los dispositivos.

### IMPORTANTE: firma de Google Play
Si el certificado de **Firma de aplicaciones** que Play Console asigna es distinto
del certificado de **Clave de subida**, copia su huella pública SHA-256 desde
`Play Console > Configuración > Integridad de la aplicación > Firma de aplicaciones`
(según interfaz) y configúrala como variable de repositorio
`SPDECODE_PLAY_APP_SIGNER_SHA256` (64 caracteres hexadecimales, sin dos puntos).
Ejecuta nuevamente el workflow antes de usar el AAB: el APK que distribuye Google
debe estar autorizado por `ReleaseIntegrity`. Una primera subida NO comprueba
automáticamente la ejecución de la APK firmada por Play.

Google Play puede distribuir el mismo paquete con otro certificado: las
instalaciones externas podrían necesitar desinstalar antes de instalar la versión
Play, con pérdida de los datos locales si los certificados difieren. Si necesitas
actualizaciones en sitio sin perder datos, configura en Play App Signing el
certificado de firma de aplicación original, siguiendo las opciones que Play
Console presente, ANTES de la primera publicación.

## Configuración del VPS durante las pruebas
Desplegar la versión nueva de API y activar explícitamente
`CLOUD_BETA_ADMISSION_ENABLED=true` en las variables del servicio web Docker,
**sin cambiar otros secretos**. En `/admin/system` usa el nuevo interruptor:
**Exigir Google Play Integrity** → desactivar. Ese acceso beta dura hasta
**15 días** y vuelve a exigir Play Integrity automáticamente si no se renueva.
Puedes reactivarlo en cualquier momento. Sin esta variable (o cuando el plazo
venza) el interruptor falla cerrado, manteniendo protección por defecto.

ADVERTENCIA: con la verificación desactivada **cualquier cliente capaz de enviar
peticiones HTTP puede solicitar una sesión**. Esto no confirma la autenticidad de
la APK; se mantienen los límites por IP, los desafíos de un solo uso, las sesiones
firmadas de cinco minutos, y la privacidad de los motores. Vigila el consumo de
la VPS. Si el cambio de política ocurre durante una sesión existente, la sesión
puede permanecer válida hasta cinco minutos.

Al publicar en producción, vuelve a activar la verificación, configura
`CLOUD_GOOGLE_SERVICE_ACCOUNT_JSON` y comprueba el certificado de Play. Los
usuarios de APK externas perderán acceso a **nuevas** sesiones sin Play.
No hay un bloqueo impuesto por Google Play al APK externo por este control:
la API decide el acceso. QA temporal continúa como mecanismo independiente.

## Preproducción externa: importaciones remotas sin QA

Las importaciones de archivos y textos operan por `CLOUD_API_ENABLED`, pero **no activan** por sí solas HTTP Injector Cloud ni Server VPN. Las tres opciones son independientes del control temporal de Google Play Integrity:

- `CLOUD_SERVER_VPN_ENABLED`: permite los proveedores Server VPN con destinos fijos aprobados.
- `CLOUD_NUR_FETCH_ENABLED` y `CLOUD_NUR_CATALOG_URL`: habilitan la importación del catálogo NUR, leyendo la URL exclusivamente del recurso privado previamente aprobado.
- `CLOUD_EHI_IMPORT_ENABLED`: permite HTTP Injector Cloud **solo** con `CLOUD_EHI_SIGN_KEY` y `CLOUD_EHI_RESPONSE_KEY` auténticas y de 32 bytes. No crear valores inventados.

En versiones antiguas, `spdecode qa start` activaba temporalmente estos servicios y `spdecode qa stop` restauraba los anteriores, dejándolos a veces deshabilitados. Desde la rama del PR #96 se administran **persistentemente y sin iniciar QA**:

```bash
sudo spdecode backup
sudo spdecode update all feat/austroplus-vpn-13-0-1-decoders
sudo spdecode providers status
sudo spdecode providers enable
sudo spdecode providers status
sudo spdecode status
```

El comando `providers enable` exige que `CLOUD_API_ENABLED=true` y que no haya una sesión QA en curso. Si hay una, ejecutar `sudo spdecode qa stop` antes de habilitar los servicios permanentes. Verifica y aplica el origen NUR sin imprimirlo. Actualiza `CLOUD_SERVER_VPN_CATALOG_VERSION` únicamente cuando cambia el estado o el origen, obligando a Android a renovar los metadatos de las opciones disponibles. Reinicia solo el servicio web y comprueba `/api/v1/ready`; ante un fallo, restaura el archivo de entorno y el contenedor.

**HTTP Injector Cloud** quedará como `NOT CONFIGURED` si faltan las claves privadas existentes. Se deben aprovisionar por un canal privado; nunca imprimirlas, registrarlas en comandos con historial o incorporarlas a GitHub. `providers enable` no genera sustitutos.

Para desactivar importaciones remotas (sin deshabilitar archivos/textos ni borrar claves):

```bash
sudo spdecode providers disable
sudo spdecode providers status
```

La habilitación de importaciones es **independiente** de la admisión beta sin Play Integrity, que se activa desde `/admin/system` y caduca en un máximo de 15 días. En la aplicación, abrir Server VPN y pulsar actualizar para consultar la nueva versión del catálogo. Si aparece un error `REMOTE_PROVIDER_UNAVAILABLE`, `REMOTE_NETWORK_DENIED` o similar, el siguiente diagnóstico es el acceso HTTPS del contenedor a los proveedores, no el modo QA del APK.

## Panel web: disponibilidad individual de proveedores (C12)

Después de actualizar la VPS, la página `https://panel.spdecode.xyz/admin/system` ofrece una sección nueva, **Disponibilidad de importaciones remotas**. Permite encender/apagar por separado HTTP Injector Cloud, NUR y los proveedores Server VPN admitidos. **No son botones de mantenimiento**: los estados se aplican tanto al catálogo público de Android como al endpoint protegido de cada descifrador. Un cambio aumenta la versión del catálogo para que Android detecte nuevos metadatos; el usuario puede forzar la actualización desde Server VPN.

**Preparación inicial del servidor**: las restricciones VPS son el máximo permitido y el panel nunca puede saltárselas. Tras detener un QA anterior, `qa stop` puede restaurar el estado antiguo `CLOUD_API_ENABLED=false`. En ese caso, configurar manualmente una vez, en la VPS:

```bash
sudo spdecode backup
sudo spdecode update all feat/austroplus-vpn-13-0-1-decoders
sudo spdecode config set CLOUD_API_ENABLED true
sudo spdecode restart web
sudo spdecode providers enable
sudo spdecode providers status
```

El panel deja los botones bloqueados para los proveedores no configurados en VPS. HTTP Injector Cloud requiere las dos claves reales del exportador y no debe activarse ni recibir claves sustitutas. Royal Tunnel permanece informativo sin descodificación remota validada.

Los interruptores autorizados y el número de versión se conservan en un **volumen Docker específico**, aislado del Redis efímero (`provider-control`), sin contraseñas ni endpoints. Los archivos VPN y datos privados no se escriben en este volumen. `spdecode providers status` describe los permisos base de VPS, mientras que el panel refleja el estado operativo individual. Mantener el volumen si se actualizan los contenedores, y no ejecutar `docker compose down -v` salvo que se desee borrar voluntariamente la configuración.

Los botones **Mantenimiento** del panel continúan siendo independientes: un servicio en mantenimiento no atenderá peticiones aunque el interruptor del proveedor esté activo. La admisión beta fuera de Play Integrity también es un control separado con caducidad máxima de 15 días.

## Provisión privada de HTTP Injector Cloud 6.5.0/244 y nombres de catálogo

Los métodos suministrados por el propietario `HTTPINJECTOR_CLOUD.py` y
`HTTPINJECTOR_EMOJI.py` confirman el protocolo HTTP Injector 6.5.0/244:
`POST /httpinjector/import_config`, firma HMAC-SHA1, HMAC-SHA256 de respuesta,
AES-256-CBC, descompresión zlib y adaptación al decodificador EHI existente.
El método emoji (`💉…🚀`) decodifica una **referencia**, no la configuración:
la aplicación ya la resuelve con el mismo contrato. La compatibilidad de
otros builds posteriores debe comprobarse con muestras reales.

El backend ya contiene el método Cloud y el codec emoji. El propietario aportó
`HTTPINJECTOR_CLOUD.py` y `HTTPINJECTOR_EMOJI.py` para cotejarlo: las dos
constantes de protocolo 6.5.0/244 coinciden con las referencias verificadas
que ya están en `HttpInjectorCloudPort.kt`. **No hace falta copiar archivos
al servidor ni utilizar Termux/computadora.**

Los archivos `decoders/Python/HTTPINJECTOR_CLOUD.py` y
`decoders/Python/HTTPINJECTOR_EMOJI.py` están incorporados literalmente
al repositorio y pueden ejecutarse como herramientas Python separadas.
El importador Cloud de Next.js ya implementa el mismo protocolo, incluidos
emojis, firma y verificación criptográfica.

El comando `spdecode providers enable` lee **automáticamente**, sin ejecutar
código, las constantes protocolarias de
`decoders/Python/HTTPINJECTOR_CLOUD.py`, confirma las
huellas criptográficas y las guarda en
`/etc/spdecode/cloud.env` con permisos 0600. Reinicia el servicio web y
restaura la configuración anterior si falla la comprobación de salud. La
clave de aplicación no se introduce de nuevo en Android ni se muestra en la
interfaz, los logs o la terminal. El motor EHI previo no cambia.

```bash
sudo spdecode backup
sudo spdecode update all feat/austroplus-vpn-13-0-1-decoders
sudo spdecode config set CLOUD_API_ENABLED true
sudo spdecode restart web
sudo spdecode providers enable
sudo spdecode providers status
```

Si existían claves privadas personalizadas incorrectas o incompletas en
`cloud.env`, el comando **no las reemplaza silenciosamente**. En ese caso
requiere revisión manual de esos valores, sin imprimirlos. La importación
`providers import-ehi` queda disponible como alternativa avanzada, pero
no se necesita para la integración normal.


En el panel `/admin/system`, el interruptor **HTTP Injector Cloud** dejará
de mostrarse sin configurar. El bloque de proveedores denomina al servicio
general **Servidores VPN**; NUR TUNNEL VPN sigue siendo **uno de los proveedores
específicos** dentro del catálogo. No confundir la marca del proveedor con el
nombre de la categoría.

Importante: `spdecode qa stop` puede restaurar `CLOUD_API_ENABLED=false`
si el estado previo a QA estaba deshabilitado. Restablecerlo una sola vez:

```bash
sudo spdecode config set CLOUD_API_ENABLED true
sudo spdecode restart web
sudo spdecode providers enable
```

## Pasos Play Console
1. Crear la ficha **SP-DECODE**, editor Ghost Nexora Studio y paquete
   `com.ghostdeveloper.spdecode`. Completar ficha, icono, capturas, política
   de privacidad y declaración de tratamiento de datos / contenido.
2. Registrar la firma Play, comparar huella SHA-256 e introducir variable de
   GitHub si es distinta. Ejecutar el workflow y obtener el AAB firmado.
3. Subir el AAB en **Prueba cerrada**. Añadir como mínimo **12 probadores**
   registrados (opt-in) durante **14 días continuos** si tu cuenta es personal
   creada después del 13-11-2023. No basta compartir la APK externa: no cuenta
   como inscripción a prueba cerrada.
4. Ofrecer un canal real de comentarios, probar login, API, archivos protegidos,
   Server VPN y novedades. Después de 14 días **solicitar** acceso a producción,
   que está sujeto a revisión, no garantizado automáticamente.
5. Incrementar `versionCode` para cada AAB nuevo; mantener siempre
   `applicationId` y la política de firma coherente.

**No publicar ni fusionar automáticamente**. La compilación produce artifacts
del workflow, no una subida automática a Play.

## Requisito Android 16 (Google Play, octubre de 2026)
A partir del 31 de agosto de 2026, las apps nuevas de teléfono/tablet
necesitan `targetSdk 36`. El proyecto usa AGP 8.9.2 (compatible con API 36),
`compileSdk 36` y conserva `minSdk 24`. Este cambio se prueba en CI, pero
se deben comprobar los gestos de navegación, barras de sistema y diálogos
en un dispositivo Android 16 antes de publicar.

## Verificación de propiedad del nombre de paquete en Play Console

Si Play Console muestra **Firma y sube un APK** para el paquete
`com.ghostdeveloper.spdecode`, este procedimiento es independiente de subir
un AAB para pruebas cerradas. **No subas aquí el AAB ni el APK beta normal**.

1. En tu repositorio GitHub, crea un secreto de Actions llamado
   `SPDECODE_ADI_REGISTRATION_TOKEN`, usando únicamente el identificador
   proporcionado por Play Console. **No publiques el identificador en código
   fuente, archivos del PR, commits, capturas de logs ni un release público.**
2. Comprueba que la huella SHA-256 indicada por Play Console sea la de la
   **clave permanente del APK existente**. La huella seleccionada durante esta
   preparación es `0F:A9:F0:7F:2C:47:46:49:25:F3:A7:B2:22:C9:A3:9E:F8:87:73:8F:67:8B:9C:91:8E:C6:C4:FB:96:16:22:60`.
   La compilación abortará si difiere: selecciona la clave elegible correcta
   en Play Console. No sustituyas ni regeneres tu keystore histórico.
3. Vuelve a ejecutar `.github/workflows/play-beta-artifacts.yml` en la
   rama de trabajo. Ese flujo compila primero el AAB y la APK beta normales.
   Después, si existe el secreto, genera un **APK independiente** que contiene
   `assets/adi-registration.properties`, firmado con la misma clave histórica.
4. Descarga el artefacto
   `SP-DECODE-PLAY-PACKAGE-OWNERSHIP-VERIFICATION` de GitHub Actions. Extrae
   `SP-DECODE-package-name-ownership-verification.apk` y súbelo en el campo
   **Firma y sube un APK** de Play Console. **No uses este APK en la pista de
   pruebas cerradas ni lo distribuyas a usuarios.**
5. Tras verificar el paquete, puedes quitar el secreto temporal de GitHub.
   Luego continúa con el AAB normal en la pista de pruebas cerradas.

El identificador se genera solamente durante esa ejecución y se destruye al
terminar; el AAB para Google Play y el APK beta externo nunca lo contienen.
La compilación no fusiona el PR, no publica en GitHub Releases y no sube
ningún archivo automáticamente a Google Play.

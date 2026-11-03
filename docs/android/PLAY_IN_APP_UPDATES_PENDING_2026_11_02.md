# SP-DECODE — fase pendiente: actualizaciones oficiales Google Play (Flexible + Inmediata)

**Fecha de decisión:** 2026-11-02  
**Estado:** PENDIENTE / DOCUMENTACIÓN SOLAMENTE. NO IMPLEMENTAR, NO PUBLICAR, NO EXIGIR CREDENCIALES AHORA.  
**Rama de referencia:** fix/http-jireh-current-method.  
**Versión de referencia del cliente:** 1.1.26 (build 41), sin incrementar como consecuencia de este documento.  
**Decisión del propietario:** actualización normal con aviso AMOLED personalizado; actualización crítica con flujo nativo Inmediato de Google Play y colores/interfaz que determine Google. No agregar barra de progreso duplicada en SP-DECODE.

## 1. Requisitos aprobados y límites

1. Al iniciar o reanudar SP-DECODE instalada desde Google Play, consultar Play In-App Updates para conocer si ese usuario tiene una versión elegible más reciente. No prometer una actualización solo porque el servidor conoce un versionCode mayor.
2. Actualización normal: ofrecer diálogo propio AMOLED, limpio y discreto, con icono de SP-DECODE, referencia a Google Play, texto localizado, botón **Actualizar ahora** y **Más tarde**. Al aceptar, lanzar el flujo **Flexible** oficial. El usuario puede seguir usando la app durante la descarga.
3. No crear otra barra de descarga en SP-DECODE. El indicador de Google Play, si aparece, es suficiente. Mostrar solamente aviso compacto **Actualización lista** cuando el estado sea DOWNLOADED, con **Reiniciar e instalar** (invoca completeUpdate) o **Después**.
4. Actualización crítica: iniciar **Immediate** de Play en vez de dibujar una falsa pantalla oficial. El sistema Play tiene control exclusivo sobre su UI, colores, textos, navegación e instalación; la maqueta vista en el chat era ilustrativa y **«SP-DECODE · Actualización crítica» no es texto oficial garantizado de Google**.
5. No interferir con importación, descifrado, exportación, HPKE, RASP, Play Integrity ni con los bloqueos por consentimiento legal. Sin ventanas superpuestas al diálogo de permisos, errores de descifrado o proceso en curso.
6. No bloquear la navegación mediante un supuesto «modo obligatorio» propio si Google Play no permite IMMEDIATE; definir cualquier política empresarial adicional por separado y con aprobación explícita. Respetar cancelaciones y errores de red.
7. Conservar compatibilidad con 14 idiomas, modo oscuro AMOLED, teléfonos compactos, rotación y accesibilidad. No utilizar logotipo oficial de Google como marca propia; si se usa, respetar sus directrices y assets sin alterar.

## 2. Arquitectura actual que debe preservarse

- Android: android/app/src/main/java/com/ghostdeveloper/spdecode/MainActivity.kt contiene availableAppUpdate, availableAppUpdateCode, refreshCloudWhatsNew() y onResume(). Actualmente obtiene una actualización propuesta por cloudNewsRepository.cachedAppUpdate(); no verifica elegibilidad de Play.
- UI: android/app/src/main/java/com/ghostdeveloper/spdecode/SpDecodeApp.kt presenta un AlertDialog para availableAppUpdate y abre https://t.me/GhostDeve. Es válido para canal externo/Telegram, no para actualizar mediante Play.
- Android Gradle: android/app/build.gradle.kts, rama Cloud. AAB y APK firmados con credenciales persistentes de GitHub; el AAB es firmado por Play App Signing al entregarlo al usuario. Mantener ambos certificados distinguidos.
- VPS: CLOUD_GOOGLE_SERVICE_ACCOUNT_JSON verifica Play Integrity con scope playintegrity; CLOUD_GOOGLE_CLOUD_PROJECT_NUMBER y credenciales FCM ya existen. **Esas credenciales no autorizan automáticamente la publicación ni sustituyen Play Developer Publishing API.**
- Mantener noticias Cloud y avisos de Telegram para instalaciones externas; **evitar dos avisos de actualización simultáneos**.

## 3. Código previsto (no escrito en esta fase)

### Dependencias y objetos
- Agregar las dependencias estables vigentes en el momento de implementar: com.google.android.play:app-update y, si conviene, com.google.android.play:app-update-ktx; verificar la versión oficial ese día. No agregar Play Billing aquí.
- Crear un coordinador Android para instalación Play, por ejemplo android/app/src/main/java/com/ghostdeveloper/spdecode/PlayInAppUpdateCoordinator.kt: crea AppUpdateManager con AppUpdateManagerFactory; representa disponibilidad, updatePriority(), clientVersionStalenessDays(), isUpdateTypeAllowed(), estado de instalación, errores y canal de distribución.
- Crear un composable de diálogo normal, por ejemplo PlayFlexibleUpdateNotice.kt: icono SP-DECODE, nombre, texto y acciones AMOLED. Sin progreso porcentual paralelo.
- Extender MainActivity para consultar al arrancar y en onResume, registrar ActivityResultLauncher compatible con el contrato actual y coordinar la navegación. Usar un solo intento por AppUpdateInfo; ante un nuevo intento consultar una instancia nueva.
- Registrar InstallStateUpdatedListener para Flexible. Al recibir DOWNLOADED presentar un aviso pequeño y llamar appUpdateManager.completeUpdate() tras confirmación. Desregistrar listener apropiadamente. Reconsultar al volver a foreground para recuperar instalaciones pendientes.
- Ante DEVELOPER_TRIGGERED_UPDATE_IN_PROGRESS reanudar Inmediata según la API.
- Separar estado UI del estado oficial de Play; callbacks del usuario no inventan descargas ni instalaciones completadas.

### Regla de decisión por actualización (propuesta pendiente de confirmar en implementación)

~~~text
app opens/resumes:
  if consent/splash/dialog critical/decode in progress: defer query/UI
  if distribution is confirmed Play-eligible:
      request AppUpdateInfo
      if availability != UPDATE_AVAILABLE: no update dialog
      else if priority >= 4 AND IMMEDIATE allowed:
          launch official IMMEDIATE flow (no custom Google replica)
      else if FLEXIBLE allowed:
          show AMOLED normal offer (throttled/dismissible)
          if accepted: start official FLEXIBLE flow
          if DOWNLOADED: show install-ready notice, call completeUpdate on approval
      else: no unsupported flow, optionally provide non-invasive Store link
  else:
      preserve the Cloud/Telegram announcement only; do not invoke Play as if eligible
~~~

- Prioridad oficial de Google: 0–5. **4–5 = candidato a crítica; 0–3 = Flexible por defecto si elegible y con control de frecuencia**, porque la prioridad 0 es la habitual de una versión publicada sin prioridad explícita. El propietario puede aprobar una ventana de espera (p. ej., antigüedad de versión) antes de desplegar el aviso para prioridad 0; no imponerla como decisión ya confirmada.
- IMMEDIATE solo si isUpdateTypeAllowed(IMMEDIATE); si no, degradar de forma segura a Flexible o informar sin bloquear; nunca presentar obligatoriedad falsa.
- Rechazo/cancelación/ERROR: restaurar SP-DECODE sin bucles. Configurar enfriamiento persistente por versionCode para aviso normal; **no silenciar para siempre una actualización futura**. Tratar cada versionCode nuevo por separado.
- Detección del instalador con PackageManager.getInstallSourceInfo en versiones nuevas (y equivalente compatible en versiones anteriores) solo como orientación; la autoridad de disponibilidad es Play. Nunca confiar en una cadena de instalador para autorizar operaciones de servidor.

### UI exacta aprobada
NORMAL: tarjeta gris grafito (#242424) sobre negro AMOLED; icono de SP-DECODE, «Nueva actualización», texto «Disponible en Google Play», versión obtenida cuando sea verificable, beneficios breves, botones claros «Actualizar ahora» y «Más tarde». No mostrar cifras simuladas ni barras de descarga creadas por nuestra app.
CRÍTICA: interfaz nativa oficial IMMEDIATE. **No** mostrar una etiqueta inventada «SP-DECODE Actualización Crítica» como si Google la proporcionara, ni intentar colorear o reescribir la ventana de Play.
FLEXIBLE DESCARGADA: aviso no intrusivo «Actualización lista», «Reiniciar e instalar»/«Después»; completeUpdate por acción explícita y reconocimiento de estado.
NO PLAY / TELEGRAM: conservar aviso del canal externo y su enlace autorizado; no mezclar con Play.

### Integración con noticias/avisos existentes
- Evitar que availableAppUpdate de Cloud y el aviso de Play coexistan; prioridad de presentación: consentimiento legal/seguridad real > operación en curso > actualización de Play disponible > novedades Cloud > update externo cuando corresponda.
- No redirigir una instalación Play a Telegram si un update Play está disponible.
- En instalaciones fuera de Play, mantener el aviso actual, con la distinción de firma entre APK externa y APK distribuida por Play; no prometer actualización in-place si los firmantes difieren.
- No agregar rutas de VPS ni secretos a la APK; no usar API de publicación desde Android.

## 4. Google Cloud/Play Console (pendiente porque el propietario no dispone ahora de conexión)

**No crear otro proyecto de Google Cloud por defecto.** Ya existe un proyecto empleado para Play Integrity y FCM.
1. Cuando haya internet, abrir el proyecto actual en Google Cloud, identificar su Project ID y comprobar si Android Publisher / Google Play Developer API está habilitada.
2. La detección Flexible/Immediate desde Android **NO requiere API key, secreto de GitHub ni servicio Google Cloud nuevo**.
3. La prioridad oficial inAppUpdatePriority se fija al publicar el lanzamiento mediante Google Play Developer Publishing API: 0–5, y no puede modificarse una vez desplegado el release. Separar el alcance de credenciales de publicación del servicio de Play Integrity del VPS.
4. Si se quiere automatizar prioridad/publicación: autorizar una cuenta de servicio con permisos mínimos sobre las pistas permitidas; preferir federación de identidad de GitHub Actions o, si no es viable, credenciales cifradas en GitHub Secrets. Nunca exponer JSON privado en chat, repo, APK ni logs.
5. Si se continúa publicando manualmente en Play Console sin API de publicación, el campo de prioridad puede permanecer en 0; por ello la experiencia normal Flexible no debe depender exclusivamente de prioridad 1–3.
6. Mantener validación del certificado de Firma de aplicaciones de Play, package ID com.ghostdeveloper.spdecode y versionCode creciente; no rotar keystore.

## 5. Plan de pruebas obligatorio antes de activar

- Unit/Compose: FakeAppUpdateManager o interfaz falsa, casos NO_UPDATE / UPDATE_AVAILABLE / IMMEDIATE_ALLOWED / FLEXIBLE_ALLOWED / NO_PLAY / NETWORK_ERROR / CANCELLED / DOWNLOADED / IN_PROGRESS; un aviso a la vez; no barra duplicada; rotación, 14 locales.
- Android real desde pista cerrada/interna: cuenta de tester, app instalada por Play, versionCode inferior, nueva versión publicada para esa cuenta, firma de Play correcta. Verificar rechazo, reintento, Flexible background + reinicio, Inmediata completa y retorno. Verificar que Android no muestre títulos ni colores falsamente prometidos.
- Internal App Sharing sirve para probar flujos básicos pero **no admite inAppUpdatePriority**; utilizar pista real de prueba para demostrar el enrutamiento por prioridad.
- APK Telegram: no invocar Play cuando no exista elegibilidad; conservar notificación Cloud y manejo de firma; ningún error fatal si Play no está disponible.
- CI: build del APK/AAB Cloud, resourceLocales, R8, firma, contratos JNI/C0 y aislamiento Cloud; cualquier cambio UI bajo política C0 requiere aprobación y hash.
- Despliegue solo después de aprobación explícita. No implementar ahora ni fusionar a main.

## 6. Criterios de aceptación para levantar el pendiente

- [ ] El propietario recuperó acceso al proyecto Google Cloud/Play Console y confirmó el estado de Publishing API (si hará falta automatizar prioridad).
- [ ] Política exacta prioridad 0, aviso y cancelación aprobada.
- [ ] Pantalla normal aprobada y crítica = UI oficial sin personalización falsa.
- [ ] Código implementado y probado en Play Closed Testing, nunca solo con APK de Telegram.
- [ ] 14 idiomas, no doble barra ni doble diálogo; C0/security/firmas CI aprobados.

## Fuentes oficiales verificadas el 2026-11-02

- https://developer.android.com/guide/playcore/in-app-updates
- https://developer.android.com/guide/playcore/in-app-updates/kotlin-java
- https://developer.android.com/guide/playcore/in-app-updates/test
- https://developers.google.com/android-publisher/api-ref/rest/v3/edits.tracks
- docs/cloud/C11_PLAY_BETA.md (documentación interna vigente); docs/cloud/C3_IMPLEMENTATION.md para Play Integrity.

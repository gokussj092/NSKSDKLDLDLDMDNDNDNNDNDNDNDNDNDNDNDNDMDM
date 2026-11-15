# SP-DECODE Admin: compilación por rama y firma persistente

Workflow: `.github/workflows/android-admin-release.yml`.

## Ejecución automática

`push.branches: ["**"]` acepta cualquier nombre de rama, incluidos nombres con
barras. Se conservan los filtros de rutas de Admin y sus contratos de backend:
un push relacionado ejecuta la compilación sin añadir la rama a una lista.

El workflow se actualiza en `main` y en `feat/android-admin-ui-improvements`,
conservando los cambios de aplicación que ya realizó Muse. Las ramas nuevas
creadas desde main heredarán el comportamiento.

GitHub usa el archivo del workflow de la rama del push. Una rama antigua que
todavía conserve la versión anterior puede incorporar esta corrección mediante
merge, o utilizar directamente la ejecución manual descrita a continuación.

## Compilar cualquier rama existente sin editarla

En Actions > **SP-DECODE Admin Signed Release** > **Run workflow**:

1. Seleccionar `main` en **Use workflow from** para utilizar esta definición.
2. En `ref`, escribir la rama, tag o SHA que se desea compilar, por ejemplo
   `feat/android-admin-ui-improvements`.
3. Ejecutar. Si `ref` se deja vacío, se compila la rama elegida en el desplegable.

El checkout utiliza exactamente ese ref. El archivo `SOURCE_COMMIT.txt` del
artefacto identifica el commit realmente compilado, que puede ser diferente
del commit de main desde el que se inició la definición del workflow.

## Una sola identidad de firma

Se utilizan exclusivamente los secretos existentes del repositorio:

- `SPDECODE_SIGNING_KEYSTORE_BASE64`
- `SPDECODE_SIGNING_STORE_PASSWORD`
- `SPDECODE_SIGNING_KEY_ALIAS`
- `SPDECODE_SIGNING_KEY_PASSWORD`

La ausencia de cualquiera detiene el trabajo antes de escribir la keystore.
No se genera una clave alternativa ni se utiliza una clave Debug como respaldo.

Una política Gradle temporal, definida por el propio workflow, configura la
keystore persistente en todos los tipos de compilación de la aplicación Admin
mediante `androidComponents.finalizeDsl`. Esto cubre también un ref antiguo
cuyo build Debug todavía emplease la firma por defecto. Tanto la compilación
como `connectedDebugAndroidTest` reciben esa política y los mismos secretos.
Los paquetes y las opciones de R8 de la aplicación seleccionada se conservan.

Antes de instalar nada en el emulador, `apksigner` verifica:

- APK release;
- APK Debug de la aplicación;
- APK de instrumentación AndroidTest.

Los tres deben tener un solo firmante y el mismo SHA-256 de certificado que
la keystore persistente restaurada. Un certificado distinto, un APK sin firma
válida o un firmante adicional detienen el trabajo.

## Pruebas y artefactos

Se mantienen los contratos de backend, pruebas nativas/JNI, lint, pruebas JVM,
R8, controles ELF/alineación de 16 KB, apertura del release en Android 15 y
pruebas instrumentadas en el emulador acelerado.

El artefacto `SP-DECODE-Admin-1.0.0-Signed-R8` solo se publica cuando todo el
trabajo anterior termina correctamente. Los informes y capturas se publican
por separado como diagnóstico incluso si hay un fallo; ese artefacto no
incluye archivos APK. La keystore temporal se elimina siempre.

Las pruebas de backend y parte de las pruebas de interfaz usan datos
sintéticos. Compilar e instalar APK reales en el emulador no equivale a
autenticar una cuenta de producción ni a validar el uso en hardware físico.
Esas pruebas necesitan cuentas/dispositivos autorizados y se registran aparte.

## Comprobaciones del cambio

`python3 -m unittest tests.test_android_admin_workflow -v` comprueba los filtros,
la selección de ref, rechazo de secretos ausentes, aplicación de la política
en ambos comandos Gradle, verificación de los tres certificados y bloqueo de
artefactos APK ante fallos. Sus respuestas de apksigner son sintéticas; la
verificación criptográfica real se ejecuta en GitHub Actions.

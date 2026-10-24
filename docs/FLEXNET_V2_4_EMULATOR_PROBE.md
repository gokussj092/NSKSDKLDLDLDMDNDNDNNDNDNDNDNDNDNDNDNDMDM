# FlexNet B46: prueba en Android virtual

24 de octubre de 2026. **Las muestras reales siguen sin descifrarse.** Se
consiguió arrancar Android, registrar el APK original y lanzar sus actividades,
pero no completar una importación estable ni obtener una captura válida.
No se confirmó ningún rechazo de atestación por parte del servidor: el fallo
observado hasta este punto está en el entorno de ejecución anterior a esa fase.

El usuario no dispone de PC ni root. Toda esta prueba se realizó en un Android
virtual separado; no requiere modificar su teléfono. Tras perderse el primer
entorno por limpieza del workspace, se recuperaron el código desde GitHub y
los archivos originales desde su almacenamiento privado, comprobando hashes.

## Entorno y herramientas

- Host x86_64 sin KVM utilizable: `-accel-check` informa que faltan vmx/svm.
- Android Emulator 37.2.12, build 16428233; CPU emulada con `-accel off`.
- Google APIs Android 11 / API 30, x86_64, revisión 16.
- `libndk_translation.so`; ABI anunciadas x86_64, x86, arm64-v8a y ARMv7.
- Frida 17.24.3 y frida-tools 14.11.0. Servidor Android x86_64 obtenido de la
  publicación oficial, SHA-256 del XZ
  `44aead87103ab9738771e5eff659640fb6bf566fe83b8629444c1be99f87ce68`.
- APK SHA-256
  `bb30b8aa5bb4207c97f19f752eeefb2fb87b417b6e491864c8508cce4c6ae5cb`.
- Muestra v6 SHA-256
  `aed8a10c90ef0ffd64af699796899ae4e32c2332d9f4dfe1dd1f8b3258647e7e`.

El [controlador](../scripts/apk_analysis/flexnet_emulator_probe.py) descarga tres
archivos oficiales del SDK con tamaño y SHA-256 fijados. Mantiene emulador,
ADB y procesos de análisis en el mismo namespace de red. Los procesos hijos
usan stdin nulo para que ADB no consuma las siguientes peticiones JSON del
controlador. El tiempo de ejecución está limitado; cierra sus procesos al salir.
No se incluye SDK, APK, AVD, captura, claves ni log real en Git.

## Observaciones comprobadas

1. `sys.boot_completed=1` se obtuvo realmente. La primera configuración usó
   720x1280 y SwiftShader; apareció un ANR de System UI, hubo reinicios de
   servicios por watchdog y el emulador terminó posteriormente con señal 11.
2. La configuración `--small` usa 384x640, GLES software legado y Vulkan
   desactivado, conservando los datos del AVD. Android volvió a arrancar.
3. `pm path`, `dumpsys package` y el resolver confirmaron paquete
   `com.flexnet.tunnel`, V 2.4, ABI principal ARM64 y launcher
   `com.betlog.baho.SplashActivity`. Una espera agotada de `adb install` no
   implicó que la instalación remota se hubiera cancelado inmediatamente.
4. Se observaron PIDs de FlexNet y solicitudes `am start` aceptadas, pero su
   historial mostró `SIGNALED`, estado 9, y `INITIALIZATION FAILURE` con
   `start timeout`. No es un error de contraseña ni un fallo de GCM observado.
5. Se copió la muestra sin alterarla y se solicitó su importación mediante
   `ConfigImportFileActivity`, ACTION_VIEW y un URI del proveedor de documentos
   con permiso de lectura. No se acreditó que finalizara esa importación.
6. Frida-server pudo transferirse e iniciarse. Los intentos de conexión dieron
   contexto PackageManager nulo durante el arranque, timeout al conectar al
   proceso del sistema y PID de FlexNet desaparecido antes de la conexión.
   No se obtuvo `FLEXNET_CAPTURE_STATUS ready` ni un registro de descifrado.
7. También se solicitó reinstalación con ABI ARMv7; ADB agotó su espera de
   180 segundos. No se confirmó esa selección final de ABI ni una importación
   posterior. Al agotarse el presupuesto del segundo emulador, dejó de estar
   disponible por ADB. Se cerró el controlador y sus procesos de análisis.

Se probaron ajustes exclusivos del laboratorio: animaciones desactivadas,
verificador adicional de instalaciones ADB desactivado, depuración temporal de
system_server y desactivación temporal de System UI. Se probó un wrapper de
inicio de la aplicación para ampliar su espera, según el código AOSP de
`ZygoteConnection`, `ProcessList` y `ActivityManagerService`. Esto no cambia el
APK ni fabrica una atestación, identidad, concesión o clave del servidor. No
se desactivó la verificación TLS de FlexNet ni sus comprobaciones de Keystore.
La conexión del depurador del sistema fue temporal. El intento de aplicar
`Watchdog.setAllowRestart(false)` mediante Frida no llegó a ejecutarse: falló
la conexión. No se atribuye el resultado a una respuesta del backend.

## Reproducción del entorno

```bash
python scripts/apk_analysis/flexnet_emulator_probe.py --prepare
python scripts/apk_analysis/flexnet_emulator_probe.py --seconds 1800 --small
```

El segundo comando acepta JSON por stdin. Ejemplos de diagnóstico:

```json
{"adb":["shell","getprop","sys.boot_completed"]}
{"adb":["shell","pm","path","com.flexnet.tunnel"]}
{"status":true}
{"exit":true}
```

Los comandos con `save_stdout` guardan salidas privadas con modo 0600. `host`
permite lanzar herramientas locales del analista; el controlador solo escucha
stdin, no abre un servicio remoto. No es un componente del bot ni del gateway.

**Dos pruebas del controlador aprobadas** con SDK ficticio: flujo de múltiples
peticiones, stdin aislado, cierre y límites de ejecución. No son pruebas de
Android ni acreditan descifrado. Comando:

```bash
python tests/test_flexnet_emulator_probe.py -v
```

La validación criptográfica previa y sus límites permanecen en
[la muestra v6](FLEXNET_V2_4_V6_SAMPLE.md) y
[el procedimiento de captura](FLEXNET_V2_4_AUTHORIZED_IMPORT.md). Para dar esta
recuperación por completada sigue haciendo falta una captura real que pase la
autenticación GCM y produzca el documento íntegro. Un APK instalado, un PID o
el arranque del sistema no sustituyen esa comprobación.

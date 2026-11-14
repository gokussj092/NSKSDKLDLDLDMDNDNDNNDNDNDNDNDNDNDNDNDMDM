# SP-DECODE Admin — Android

Módulo Android independiente en la rama `feat/android-admin-panel`. Paquete `com.ghostdeveloper.spdecode.admin`; debug utiliza el sufijo `.preview`. No modifica los clientes Cloud/Offline ni el backend.

## Interfaz e interacciones integradas

La interfaz nativa Compose sigue las referencias AMOLED: negro puro, superficies oscuras, acento menta, tarjetas redondeadas, iconos lineales y navegación inferior/lateral. Incluye ajustes de teclado, listas desplazables, modo horizontal, pantallas pequeñas y temas AMOLED/oscuro/claro.

- **Acceso y resumen:** identidad SP-DECODE, campos visuales de ejemplo, métricas y actividad vinculadas a los módulos.
- **Usuarios:** búsqueda, orden, filtros, alta/edición con validación, detalle individual, compras/licencias/sesiones/actividad de la cuenta seleccionada y suspensión/reactivación sin perder el plan Premium.
- **Roles y personal:** creación y edición de cargos, miembros, nombres visibles y permisos con dependencias. El cargo propietario permanece protegido.
- **Soporte:** bandeja con búsqueda, no leídos y filtros; chat privado, borrador, mensajes locales identificados, asignación de agente y cierre/reapertura de tickets. El compositor se adapta al teclado.
- **Finanzas:** periodos de 7/30/90 días, ingresos netos calculados sobre pedidos completados, gráfica, ventas, pendientes y distribución por método. Pedidos pendientes/reembolsados no aportan ingresos.
- **Transacciones:** búsqueda por pedido, producto, usuario o proveedor, filtros de estado, detalle, importe histórico inmutable y cambios de estado de demostración.
- **Productos:** edición de nombre, descripción, precio exacto en centavos y disponibilidad. Los cambios no reescriben pedidos anteriores.
- **Licencias:** búsqueda, filtros, contadores, generación DEMO con usuario/dispositivos/vigencia, detalle, copia, revocación y restauración.
- **Gift codes:** recompensa, usos, caducidad, dispositivos, generación DEMO, copia, historial y revocación/restauración. No genera códigos canjeables reales.
- **API comercial:** métricas, búsqueda/filtros, alta y edición de cliente con una sola IP literal IPv4/IPv6, clave DEMO, renovación y revocación/restauración.
- **Créditos:** saldos por usuario, ajustes con motivo y límites, prevención de saldo negativo e historial.
- **Servidor:** instantánea visual de CPU/RAM/disco/uptime/servicios y estado de mantenimiento de demostración. Actualizar la vista no consulta el VPS.
- **Catálogo:** búsqueda/filtros, cambios preparados, descarte y publicación atómica de prueba que incrementa la versión y añade un aviso local. No altera los métodos reales.
- **Avisos:** centro con leídos/no leídos, destinos, editor por idioma, audiencia/tipo, aviso dentro de la app, selección de idiomas, vista previa RTL y registro local de la simulación.
- **Actividad:** búsqueda/filtros, niveles, tiempos y exportación CSV mediante el selector de documentos de Android, con escape de fórmulas.
- **Seguridad, sesiones, mantenimiento y ajustes:** navegación, estados y acciones locales explícitas, cierre de registros de sesión de prueba, caché de ejemplo, exportación JSON de datos ficticios y preferencias de apariencia/indicadores persistidas.

Los avisos usan los 14 locales del cliente actual: español, inglés, portugués de Brasil, francés, alemán, italiano, árabe, persa, ruso, turco, hindi, indonesio, vietnamita y japonés. Incluyen textos iniciales completos para actualización de catálogo; los cambios del autor se editan por idioma y no se anuncian como traducciones automáticas. La interfaz administrativa de esta revisión está en español.

## Alcance real y puerta de producción

**Este APK sigue siendo una revisión interactiva sin conexión al servidor.** No tiene permiso INTERNET, no acepta contraseñas reales y conserva los datos de demostración en memoria durante la vida del proceso. Solo persiste preferencias de pantalla. Todas las claves emitidas son DEMO y no conceden acceso real. Release permanece deshabilitado.

Se recuperó el paquete anterior de integración UI/JNI y se incorporó su planificador C++17 de 15 operaciones administrativas, con métodos, rutas, límites y codificación de consultas. `AdminApi.kt` prepara HTTPS/OkHttp, cookies y sesión en memoria; la Activity no construye ni utiliza ese cliente.

La autenticación administrativa real, MFA, biometría, Keystore, autorización por permisos en servidor, acciones comerciales remotas, recepción push, adjuntos y supervisión real del VPS siguen pendientes de integrar y validar. No se han procesado cobros, reembolsos, licencias, mensajes ni notificaciones reales. Los controles pendientes explican su estado y no simulan protección activa.

## Compilación y comprobación

JDK 17/21, Gradle 8.11.1, SDK 35, NDK 27.2.12479018, CMake 3.22.1:

```sh
./android-admin/gradlew -p android-admin :app:assembleDebug :app:lintDebug :app:testDebugUnitTest :app:assembleDebugAndroidTest
sh android-admin/tests/run-native.sh
sh android-admin/tests/run-jni-host.sh
./android-admin/gradlew -p android-admin :app:connectedDebugAndroidTest
```

APK: `android-admin/app/build/outputs/apk/debug/app-debug.apk`.

El workflow `SP-DECODE Admin Android Preview` compila, revisa, prueba y captura las pantallas en Android API 35 con KVM. Las pruebas de dispositivo cubren además teclado en 320 dp con texto al 130%, modo horizontal y tema claro. Los artefactos incluyen APK, resultados, informe de revisión estática y capturas. La firma es de debug, no la firma de producción de Cloud/Offline.

[Pruebas](tests/README.md) · [Estado de validación](VALIDATION.md)

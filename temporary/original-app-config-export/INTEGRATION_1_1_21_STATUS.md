# Reanudar integración 1.1.21

Cuenta autorizada: Goku (`gokussj092`), repositorio migrado y misma rama
`feat/temporary-original-app-config-export-lab`. No fusionar ni desplegar VPS.
El usuario autorizó implementar Android/API y actualizar workflows a 1.1.21;
notificaciones del sistema se aplazan expresamente.

## Recuperación y respaldo

La limpieza eliminó el checkout anterior. Se recuperaron los 1981 archivos
del commit `7a17961bf7d806454940c68302e54841c3d9c972` mediante el conector Goku,
verificando cada objeto Git contra su SHA-1. El índice y los árboles coinciden.
Los paquetes privados de pruebas siguen recuperables desde las entregas
anteriores; no se incluyen en commits ni en logs. Una copia local por sí sola
no garantiza sobrevivir otra limpieza: cada hito se guarda en esta rama.

## Hito 1: worker de exportación

- Adaptadores en `cloud/workers/python/exports/` para HC, Dark, EHI y NPV.
- Artefactos preparados después de un descifrado válido, en proceso aislado,
  límite 1 MiB y presupuesto de respuesta completa inferior a 6 MiB.
- HC reconstruye n11 abierto con HTML y retira password/HWID después de
  autenticar; conserva perfiles, expiración y secciones desconocidas.
- NPV puede reconstruir NPVO1 después de passphrase o private key v5/v6
  validada por el lector existente; las políticas no representables se rechazan.
- EHI usa la ruta abierta + HTML aceptada. La derivación de HMAC usa la
  huella **pública** del certificado auditado, sin necesitar distribuir su APK.
- Dark conserva la política sin banner. El bridge distingue JSON abierto de
  los contenedores protegidos antes de elegir el lector.
- 12 pruebas de exportación y tres contratos de integración pasan. Las cuatro muestras originales recuperadas de
  las entregas privadas producen artefactos locales verificados.
- Las ampliaciones de credenciales tienen comprobación criptográfica local;
  todavía requieren nuevas importaciones manuales en las apps originales.

## Decisión de historial

Se mejora el plan de RAM temporal a petición del usuario: almacenar el
artefacto preparado dentro del registro cifrado del historial. El archivo
podrá guardarse después de reiniciar, sin conservar la contraseña/HWID/key
de apertura. Los registros históricos antiguos sin artefacto requieren
volver a descifrar la fuente. No reconstruir desde JSON de presentación.

## Hito 2: API, catálogo y panel

- Protocolo aditivo `X-SPDecode-Compatible-Export: 1` y versión >=1.1.21.
  Los clientes anteriores conservan el esquema y la versión de catálogo.
- El panel administra habilitación y versión mínima (nunca inferior a 1.1.21).
  Configuración desactivada por defecto, persistente en `provider-control`,
  escrituras atómicas, revisiones concurrentes y autenticación/CSRF existentes.
- El apagado de exportación conserva el descifrado y su JSON. La capacidad
  nueva no reemplaza autenticación, mantenimiento ni autorización de archivos.
- Una política ilegible bloquea solo la preparación, con código fijo
  `EXPORT_POLICY_UNAVAILABLE`; el worker recibe el decode normal sin opción.
- Interruptor de emergencia `CLOUD_COMPATIBLE_EXPORT_LOCKED` conectado al
  compose y a la allowlist del CLI; no se ha cambiado ningún VPS.
- Las 355 pruebas Node del sitio/API pasan, incluyendo versión antigua,
  versión mínima, manipulación de opciones, persistencia y controles del panel.
  `next build` también pasó. La compilación no activa servicios externos.

## Hito 3: Android 1.1.21 y validación

- DTO con SHA-256 de fuente, texto y artefacto, límites y metadatos fijos.
- Historial cifrado v3 compatible con v1/v2. Guardado binario con SAF desde
  el resultado o el registro seleccionado, sin almacenar claves de apertura.
- Exportar para [aplicación] sustituye Original solamente en el menú Exportar
  Cloud de los cuatro formatos. Copiar y las nueve fuentes C0 se conservan.
- Versión 1.1.21 / 32 y cinco workflows históricos actualizados. Workflow
  adicional de validación para esta rama, sin empaquetado ni publicación.
- `compileDebugKotlin` y `compileDebugAndroidTestKotlin`: **BUILD SUCCESSFUL**.
  Compilan las pruebas de integridad/historial; no se ejecutaron en Android.
- Regresiones Cloud: 94 pasan; worker: 16; instalador/controles VPS: 56.
  Los contratos nuevos y relacionados de Android se verificaron por separado.
- C++ del transporte pasa comprobación de sintaxis con JNI. Auditoría S.3
  final sin hallazgos de credenciales/logs en los 2023 archivos rastreados.
- No se generó APK/AAB, desplegó VPS ni fusionó main. Compatibilidad de la
  **integración nueva** pendiente de prueba en teléfono y aplicaciones VPN.

## Fallos reproducidos y correcciones

- Workflow Play seguía buscando nombres 1.1.20: falló su regresión al cambiar
  Gradle. Se actualizaron nombres, asserts y códigos de los workflows afectados.
- `prepareCloudHistoryUiSource` esperaba la firma vieja de `decodeFile` y
  rechazó el build. Se actualizaron ambos anchors conservando el permiso de
  password anunciado por catálogo y el callback del artefacto. Compilación pasa.
- Tres casos de regresión requerían PHP ausente en el entorno; con PHP local
  pasan sin modificar sus goldens ni los decodificadores.
- Dark abierto fallaba en el lector protegido antiguo; el bridge identifica
  el contenedor antes de elegir el lector. No hace fallback tras fallo de auth.
- El presupuesto de 25s del decode era menor que decode + export aislado:
  se amplía solo esa solicitud a 50s en broker y 55s en Android. La ruta
  Nginx de archivo espera 65s; los otros presupuestos se conservan.
- La revisión del formato Dark confirmó que la salida abierta no conserva el
  carrier de expiración del wrapper: ahora rechaza expiración no cero para
  exportación. El JSON descifrado sigue disponible. Hay prueba sintética.

## Próxima prueba manual

Seguir `INTEGRATION_1_1_21.md`: actualizar web/worker e instalar la app por el
procedimiento del operador; activar la tarjeta del panel con mínimo 1.1.21.
Verificar resultado, historial tras reinicio, guardado SAF e importación real
HC/Dark/EHI/NPV; controles password/HWID/private key y clientes 1.1.20/1.1.21.
Notificaciones quedan aplazadas. No declarar compatibilidad global por roundtrip.

Este archivo debe actualizarse en cada hito; los commits remotos son el
respaldo durable del código. No guardar el repositorio otra vez como archivo
duplicado en las entregas de documentos.

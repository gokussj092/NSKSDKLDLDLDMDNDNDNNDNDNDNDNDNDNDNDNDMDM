# Server VPN — fase 1: directorio Android

## Alcance

Esta fase afecta únicamente a la aplicación Android. No cambia los contratos
de Cloud, los proveedores, la versión del catálogo ni sus iconos; no requiere
reiniciar Redis ni desplegar una actualización en el VPS.

- La cabecera «Server VPN» incluye un botón circular con icono de recarga
  **visible en todo momento en compilaciones Cloud**. Ejecuta el callback ya
  existente `onRefreshServerVpn={refreshServerVpn(force=true)}` de
  `MainActivity`, que invoca `ServerVpnCatalogRepository.refreshIfDue(force=true)`.
  La consulta manual **no depende del intervalo automático de 15 minutos**.
- Se bloquean toques repetidos mientras hay una actualización o decodificación,
  y se muestra un indicador de actividad hasta que termina la petición.
- El campo «Buscar aplicaciones VPN» busca nombre visible e identificador de
  proveedor, sin distinción entre mayúsculas y minúsculas ni consultas de red.
- Filtros excluyentes: **Todas**, **Disponibles** (`decodeEnabled=true` en el
  catálogo firmado/verificado) y **Favoritas**. Los resultados se ordenan por
  nombre e ID. «Disponible» **no es una comprobación de salud de la API**.
- La estrella alterna un favorito por ID estable del catálogo. La elección
  persiste entre aperturas y actualizaciones normales de la APK mediante
  `SharedPreferences` privadas, separadas del historial y las credenciales.
  Solo se almacenan IDs públicos de proveedores, nunca servidores o resultados.
- Los favoritos sobreviven a cambios de versión de catálogo si reaparece el
  mismo ID. Se pierden al borrar los datos de la aplicación o desinstalarla.
- La lista se representa con `LazyColumn`, conservando iconos originales,
  expansión de tarjetas y llamadas previas a descifrar servidores.
- Se mantiene la pantalla anterior de NUR Tunnel en variantes offline.
- Textos añadidos en los nueve directorios de recursos actuales.

## Comportamiento de red y caché

Una pulsación manual obliga a consultar el contrato de versión del catálogo
a través de la API, aunque exista caché local verificada. Si la versión remota
no cambió, el servidor puede devolver `unchanged`, evitando volver a descargar
iconos. Si la API no responde, el repositorio conserva el último catálogo
válido y el botón puede usarse para reintentar. **No confundir fin del indicador
de carga con una garantía de disponibilidad remota**: el repositorio conserva
la política de recuperación silenciosa de la fase anterior.

La sincronización automática continúa siendo independiente: consulta de
versión mientras la app está visible y recuperación opcional con WorkManager.
El usuario puede usar el botón manual aunque desactive la sincronización
en segundo plano. La aceptación de condiciones Cloud sigue siendo requerida.

## Pruebas y checklist de publicación

Pruebas instrumentadas en
`android/app/src/androidTest/java/com/ghostdeveloper/spdecode/ServerVpnDirectoryInstrumentedTest.kt`:
búsqueda por nombre y ID, filtros, ordenación, persistencia y validación de IDs.

Antes de publicar una APK/AAB:
1. Verificar el build Android Cloud y las transformaciones del código generado
   en `prepareCloudHistoryUiSource` / `prepareCloudOnlySources`.
2. Abrir Server VPN sin caché y con caché, pulsar actualizar, buscar y cambiar
   filtros durante la carga.
3. Guardar favoritos, cerrar y reabrir, actualizar el catálogo y comprobar que
   permanecen asociados a los mismos IDs.
4. Revisar dispositivos pequeños, modo RTL (árabe y persa), accesibilidad y
   los nueve idiomas.
5. Comprobar que el catálogo falla sin borrar una copia válida y que la
   consulta manual no intenta saltarse el consentimiento Cloud.

Rama prevista: `feat/austroplus-vpn-13-0-1-decoders`, PR #96.
Sin merge a `main`, sin despliegue y sin publicación automática.

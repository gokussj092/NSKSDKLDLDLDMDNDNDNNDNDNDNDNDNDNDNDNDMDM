# SP-DECODE — Indicadores de progreso Cloud (2026-11-02)

## Alcance aprobado
Todas las solicitudes de descifrado Cloud muestran, además del texto de espera y del indicador de carga existente, las fases localizadas **Enviando**, **Procesando** y **Descargando resultados**. Se aplica a importaciones de uno o varios archivos, configuraciones de texto, enlaces de Nube global (HTTP Custom e HTTP Injector) y catálogos Server VPN (NUR y proveedores). Los 14 idiomas configurados disponen de textos propios.

## Modelo de eventos
- **Enviando:** solicitud preparada por Android; incluye el establecimiento/autorización de la sesión segura antes del envío al endpoint nativo.
- **Procesando:** sesión lista; la operación protegida entra en el transporte nativo y se espera la respuesta del servidor. La duración incluye controles de integridad y operación remota.
- **Descargando resultados:** la respuesta completa ha llegado al cliente y está siendo recibida/validada/presentada para guardado; **no** se afirma disponer de telemetría de descarga por bytes ni de eventos streaming del backend.

No hay porcentajes, tiempos estimados, cronómetros ni cambios simulados para aparentar progreso. La pantalla conserva las leyendas previas (lectura, descifrado, guardado) y añade la fase Cloud únicamente mientras hay un trabajo activo. Al cancelar o finalizar, la fase se restablece. El identificador de generación evita que una solicitud cancelada cambie el estado de la siguiente.

## Frontera de seguridad
La incorporación es de UI: `CloudDecodeClient.TransferPhase` únicamente enumera hitos de presentación. Los métodos de descifrado del servidor permanecen en el backend; las rutas de API y el cifrado/transporte HPKE permanecen en C++/JNI. No se añadieron endpoints, claves o información de servidor a Kotlin.

## Pruebas y controles
- `tests/test_cloud_transfer_progress.py` verifica recursos de 14 idiomas, rutas Cloud y sincronización del estado con la solicitud activa.
- `docs/cloud/C0_UI_APPROVED_1_1_26.json` fija el nuevo hash exacto de `SpDecodeApp.kt`; `C0_UI_BASELINE.json` sigue intacto.
- Ejecutar los pipelines de GitHub Actions Cloud (C0–C8, JNI, V2, seguridad) y las pruebas instrumentadas antes de aprobar distribución.
- Las verificaciones históricas de descifrado Android offline siguen fuera del pipeline Cloud; no se vuelven a integrar en el APK de producción.

No fusionar a `main`, no incrementar versión ni distribuir APK/AAB de producción sin revisión de los gates.

# Registro de nuevas integraciones VPN

Este registro reúne únicamente las incorporaciones del lote iniciado con
HTTP SocketClay. Se utilizará como fuente para una futura actualización de
novedades cuando el usuario la solicite. No arrastrar funcionalidades de
entregas anteriores ni publicar anuncios automáticamente.

- Rama de trabajo: `feat/austroplus-vpn-13-0-1-decoders`.
- PR: [#96](https://github.com/Gh0stDeveloper/SP-DECODE/pull/96).
- Inicio del lote: 2026-10-20.

## Nuevos Servidores VPN añadidos

Todavía no hay incorporaciones confirmadas en este lote.
Añadir aquí una línea con el nombre de la aplicación y ✅ solamente después
de verificar e integrar su catálogo. Conservar las líneas anteriores al
incorporar más aplicaciones.

## Nuevos métodos de archivos, textos o enlaces añadidos

Todavía no hay incorporaciones confirmadas en este lote.
Si una aplicación solo admite archivos o enlaces, registrarla en esta
sección; no anunciarla como un servidor VPN nuevo.

## Integraciones pendientes

### HTTP SocketClay — versión indicada 3.4.0

- Adjunto recibido: `HTTP SocketClay_3.4.0.zip`.
- Estado: **pendiente de análisis e integración; no habilitado**.
- Bloqueo observado: el entorno de ejecución del chat está no disponible;
  no fue posible abrir el ZIP ni ejecutar las herramientas de análisis.
  El adjunto ya está aportado; no hace falta solicitarlo nuevamente.
- Nombre, paquete y versión interna del APK: por comprobar.
- Catálogo remoto, archivos exportados, extensiones y enlaces: por identificar.
- Descifrado, comparación del JSON completo y pruebas reales: pendientes.
- Scripts, icono original y documentación de la aplicación: pendientes.
- No se ha añadido un motor, proveedor, ficha de catálogo ni anuncio de
  HTTP SocketClay. Esta entrada no acredita compatibilidad.

Al continuar, analizar el ZIP aportado y seguir la organización
`decoders/Python/apps/<APP_NAME>/`. Crear lectores separados de catálogo y
archivos únicamente para los mecanismos que existan realmente. Conservar
los métodos anteriores y todos los campos de las configuraciones.

## Cómo completar el registro

Al terminar cada integración:

1. Mover su nombre a la sección confirmada que corresponda, con ✅.
2. Registrar versión de app, alcance confirmado, carpeta, pruebas realizadas,
   limitaciones pendientes y commit/PR. No incluir credenciales, respuestas
   privadas, URLs internas ni datos descifrados.
3. Distinguir integración en código de disponibilidad tras despliegue.
   Si falta una comprobación necesaria, conservarla como pendiente.
4. No generar ni publicar todavía `whats-new.json`. Cuando el usuario pida
   preparar las novedades, utilizar solo las incorporaciones confirmadas
   de este lote y respetar las versiones y cachés de cada sistema.

Leer también [la guía de integración](SERVER_VPN_NEXT_CHAT_GUIDE.md) y
[el procedimiento de actualización de catálogos y novedades](CATALOGS_UPDATE_RUNBOOK.md).
Server VPN y What's New tienen versiones independientes. Una modificación
de este registro, por sí sola, no cambia ninguno de esos catálogos.

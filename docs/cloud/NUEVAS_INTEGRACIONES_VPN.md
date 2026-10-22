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

- **HTTP SocketClay 3.4.0 ✅ — archivos `.sks`**: lector Python y ruta Cloud
  compartida con Fenix/Jireh. GCM y DES comprobados con el importador del APK y
  vectores Java sintéticos; exportación real independiente no proporcionada.
  Carpeta: `decoders/Python/apps/HTTP_SocketClay/`, PR #96. No se añade otra
  extensión ni se modifica Android. Esto no habilita su catálogo remoto.

## Integraciones pendientes

### HTTP SocketClay — 3.4.0, versionCode 341

- Adjunto analizado: `HTTP SocketClay_3.4.0.zip`; paquete `com.socketclay.http`.
- **Código integrado**: lectores separados de archivos y catálogo, manifiesto,
  icono original, documentación y pruebas bajo `decoders/Python/apps/HTTP_SocketClay/`.
- Catálogos actuales incluidos en el APK: JSON completo de 1 servidor y 2
  entradas de usuarios, paridad Java/Python y 17 campos no vacíos verificados.
  No confundir con disponibilidad o cantidad de servidores remotos actuales.
- Método actual: WakkoDev/MD5/AES-CBC, envoltura ChaCha20-Poly1305 de campos,
  clave derivada de versión y Java ROT19. KDF nativo contrastado para cuatro
  versiones. Worker aislado con ID `http-socketclay`, sin red.
- `.sks` GCM/DES reutiliza el motor existente; fuente e icono de 431×426
  comprobados. No se identificó otro lector propio de enlaces.
- **Pendiente de consulta remota y habilitación**: la revisión automática rechazó
  acceder a las fuentes externas de servidores y usuarios por su posible
  contenido de credenciales; requiere autorización explícita antes de reintentar.
  No se intentó otro host ni herramienta. El bloqueo antiguo del entorno ya no
  aplica: se abrió el ZIP y se completó el análisis local.
- Tarjeta presente con `remote:null` y descifrado desactivado; versión mínima de
  Server VPN **14**. No se registra aún un broker externo sin validar.
- Ramas y cambios anteriores conservados. No se modifican novedades C11 ni
  se afirma disponibilidad tras despliegue. Ver README/TESTING del lector.


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

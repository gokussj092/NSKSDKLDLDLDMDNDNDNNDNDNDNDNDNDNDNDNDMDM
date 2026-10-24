# Historial de cambios

## Android 1.1.19 (build 30) — catálogo Cloud dinámico (preproducción)

- La importación Cloud vuelve a consultar el último catálogo de extensiones verificado en caché cifrada, incluso si una actualización en segundo plano llegó después de abrir la aplicación.
- La pestaña Formatos carga el catálogo previamente descargado aunque la actualización automática esté desactivada. La descarga manual mantiene la confirmación; con autoactualización activada se comprueba una sola vez el catálogo al importar una extensión desconocida.
- Se conservan los `credentialFields` del catálogo remoto para reconocer motores nuevos que solicitan contraseña. El backend sigue autorizando cada extensión y credencial; el APK no descarga ni ejecuta código de decodificación.
- Reconocimiento de extensiones Unicode conforme a los metadatos remotos y pruebas con un sufijo futuro que no existe en el catálogo local.
- Versión privada de QA/preproducción. No fusionada, no desplegada y no publicada; CI y pruebas en dispositivo son obligatorias.

## SocksIP 15.14.4 y separación de HTTP Injector Lite 2026-07-23

- Verificado el ZIP completo y analizado SocksIP 15.14.4, incluidos sus tres DEX y la biblioteca nativa.
- Confirmado que esta compilación usa Base64, AES-128-ECB/PKCS#7 y serialización Java, sin una ruta `VER7`.
- Mejorado el diagnóstico de las muestras `VER7` para indicar que pertenecen a otra variante en vez de solicitar de nuevo el mismo APK.
- Creado `HTTPINJECTORLITE.py` como decodificador Python independiente para `.ehil`.
- Eliminada toda la lógica Lite de `HTTPINJECTOR.py`, que queda reservado para HTTP Injector normal `.ehi`.
- Añadida una validación de registro que impide que `.ehi` y `.ehil` vuelvan a compartir script.
- Añadidas pruebas de aislamiento entre formatos y de detección explícita de SocksIP `VER7`.

## Campos internos y HTTP Injector Lite 2026-07-23

- Añadido el descifrado recursivo de valores NoobCrypt AES-256-GCM dentro del JSON de Maya y XUI.
- Verificada la etiqueta GCM antes de reemplazar cada valor; las cadenas Base64 comunes permanecen intactas.
- Sustituido el registro antiguo `.ehil` por el decodificador Python actual para HTTP Injector Lite 5.4.0.
- Añadidas las dos capas AES-CBC de Lite y la decodificación de campos internos con su alfabeto Base64 propio.
- Probadas las muestras reales de Maya, XUI y HTTP Injector Lite.
- Ampliado el conjunto a catorce pruebas automatizadas.
- Confirmado que las dos muestras SocksIP usan `VER7`; la implementación queda pendiente de recibir completo el APK 15.14.4.

## Integración de tres aplicaciones 2026-07-23

- Actualizado Maya Tunnel `.maya` al método NoobCrypt AES-256-CBC de la muestra suministrada.
- Añadido XUI Tunnel `.xui` con su clave actual y extracción del JSON prefijado.
- Añadido SocksIP Tunnel `.sip` para el formato AES-ECB con serialización Java generado por el APK suministrado.
- Añadida detección explícita del contenedor SocksIP `VER7`, que requiere el APK exacto de esa variante.
- Registradas 54 extensiones en total.
- Añadidas tres pruebas funcionales generadas para Maya, XUI y SocksIP.

## Entrega acumulativa 2026-07-23

- Fusionados TLS Tunnel y e-V2Ray en una sola base.
- Registradas 52 extensiones sin rutas faltantes.
- Aplicada una autorización central a archivos, protocolos de texto y fallback.
- Eliminados `config.json`, credenciales incrustadas y archivos de permisos heredados de la distribución.
- Añadido soporte opcional para `SPDECODE_BOT_TOKEN`.
- Eliminado `node_modules` del paquete; la instalación reproducible usa `npm ci`.
- Fijadas versiones de dependencias Python y Node.js.
- Añadida ruta criptográfica alternativa para TLS mediante `cryptography`.
- Incorporadas pruebas unitarias de acceso y fixtures funcionales de TLS/e-V2Ray.
- Extendida la validación estática para comprobar permisos, secretos y dependencias.

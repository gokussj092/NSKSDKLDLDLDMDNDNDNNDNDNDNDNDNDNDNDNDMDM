# Validación de SP-DECODE Admin conectado

Revisión en desarrollo sobre `d90a10fd030bfbcc012b952983fdff539cc82e46`.

## Comprobado localmente

- Rutas C++: PASS.
- Compilación del transporte con C++17, `-Wall -Wextra -Werror -pedantic`: PASS.
- Puente JNI y transporte HTTPS mediante fixture JVM: PASS; URL fija, POST, límites, cookies, rechazos y UTF-8.
- Backend: 24 pruebas PASS (mobile, personal/permisos/soporte y autenticación administrativa).
- Datos, controles y fuentes de demostración retirados del código de la aplicación.

## Por registrar tras CI

- Compilación Android release y ejecución de R8.
- Verificación de la firma permanente contra los secretos existentes.
- Revisión estática, pruebas instrumentadas y apertura del APK release en Android 15.

## Producción

Se debe desplegar `/api/admin/mobile` de esta rama antes de utilizar las nuevas lecturas comerciales. Las pruebas locales no han utilizado credenciales administrativas de producción, ni han realizado pagos, reembolsos, cambios de catálogo o notificaciones reales. No se afirma una validación autenticada del VPS ni una prueba en hardware ARM físico.

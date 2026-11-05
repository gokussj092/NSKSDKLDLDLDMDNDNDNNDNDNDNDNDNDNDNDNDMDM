# Controles separados de mantenimiento por proveedor — 2026-11-05

## Problema reproducido en código

En \`/admin/providers\`, la primera lista solo mostraba un interruptor de disponibilidad, mientras que el mantenimiento por método se escondía en otra lista extensa al final. El backend exponía únicamente \`enabled\` como **estado efectivo**, no como preferencia manual, de modo que un proveedor en mantenimiento aparecía erróneamente «Deshabilitado desde el panel» y el control manual podía parecer desactivado. \`/admin/maintenance\` ofrecía mantenimiento general/por servicio, pero no mantenimiento individual de cada catálogo.

## Corrección

- La lista de proveedores ahora muestra dos controles distintos y con etiquetas visibles: **Mantenimiento** (estado de método) y **Habilitado** (preferencia del administrador). El indicador de mantenimiento prevalece en el estado visible y evita nuevos descifrados; el interruptor de disponibilidad no desactiva el mantenimiento.
- \`/admin/maintenance\` incorpora la lista buscable de métodos Server VPN, incluso entradas no descargables, con pausa y reanudación individual.
- El backend añade \`disabledProviderIds\` al resumen administrativo (sin alterar \`providers[].enabled\` para el catálogo ni el contrato Android). Se consulta el estado manual persistente y no se infiere de la disponibilidad efectiva.
- \`/api/admin/provider-methods\` mantiene autenticación, protección CSRF, validación de IDs, volumen persistente, bloqueo real de descifrado y subida de \`catalogVersion\`. En la respuesta pública del catálogo permanece \`maintenance:true\` con \`decodeEnabled:false\`.
- «Marcar actualizado» continúa siendo independiente. La sección de revisiones sigue accesible en la vista de proveedores. No se han alterado métodos de descifrado, direcciones de terceros, claves ni APK/AAB.

## Pruebas y despliegue

Se agregan pruebas de regresión del estado administrativo independiente y verificaciones estáticas de los controles de las dos vistas. Ejecutar en un entorno con Node 22+ y el repositorio completo:

\`\`\`sh
cd cloud/web
node --test tests/c12-provider-controls.test.mjs tests/admin-provider-maintenance.test.mjs tests/admin-sidebar-navigation.test.mjs
npm run build
\`\`\`

Después de actualizar y reconstruir **web** en el VPS, comprobar con una cuenta administradora \`/admin/providers\` y \`/admin/maintenance\`, activar mantenimiento en un proveedor de prueba, constatar el nuevo \`catalogVersion\` y un catálogo con \`maintenance:true\` y \`decodeEnabled:false\`; deshacer el estado y verificar \`maintenance:false\` sin habilitar indebidamente un proveedor previamente desactivado. La modificación en GitHub **no equivale a despliegue ni a una prueba operativa en la VPS**.

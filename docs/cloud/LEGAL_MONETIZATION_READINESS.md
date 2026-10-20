# SP-DECODE — monetización futura y documentos legales

Actualizado: 2026-10-19. Rama de desarrollo: `feat/austroplus-vpn-13-0-1-decoders`.

## Estado de este cambio

Esta tarea **solo modifica los textos de las páginas públicas** `/terms` y `/privacy` en español e inglés, más las pruebas web. No instala SDK de publicidad, no activa anuncios, no vende suscripciones, no modifica la aplicación Android ni su backend. La suscripción mensual propuesta tendrá como beneficio **retirar los anuncios de SP-DECODE**, sin dar privilegios de descifrado adicionales.

Los textos siguen siendo **borradores sujetos a revisión jurídica**. La activación comercial requiere un nuevo cambio y una comprobación técnica/contractual.

## Lista de verificación antes del lanzamiento

1. Elegir la red publicitaria y verificar qué datos recoge efectivamente su SDK (identificador publicitario, IP, diagnóstico, interacciones, etc.), países de operación, destinatarios, transferencias y plazos de retención. Añadir los nombres y enlaces reales a la política y configurar avisos/controles de consentimiento u oposición según el país.
2. Definir Google Play Billing u otro proveedor permitido por el canal de distribución; precio por mes, moneda/impuestos según país, renovación, períodos de prueba/descuentos si existen, cancelación y reembolso aplicables; mostrar todo **antes de confirmar el pago**.
3. Verificar y revocar de forma segura los derechos de suscripción en la aplicación y, si se usa, en el servidor: purchase token, estado, fecha y restauración de compras. No solicitar ni almacenar números completos de tarjeta.
4. Incorporar en Ajustes un acceso directo a la gestión/cancelación de suscripciones, así como controles de privacidad según el proveedor y el territorio. Eliminar anuncios en toda la experiencia de SP-DECODE cuando el derecho de pago esté activo.
5. Actualizar la ficha de **Seguridad de los datos**, la declaración de identificador publicitario y la audiencia en Play Console para que coincidan con el manifiesto fusionado y el tráfico real, incluidos los SDK. No elegir arbitrariamente 18+ solo para eludir reglas infantiles.
6. Comprobar los procesos y tiempos de retención de registros, derechos de privacidad, contacto real, identidad legal del responsable y posibles requisitos de protección a menores o regiones específicas. No declarar falsamente que no se comparten datos sin auditar a los proveedores.
7. Revisar si el cambio legal exige nueva aceptación y actualizar **de manera coordinada** la versión/fecha de consentimiento de la aplicación Android. La publicación de nuevas cláusulas en la web no modifica por sí sola el consentimiento que ya quedó guardado en el dispositivo.
8. Pasar por revisión jurídica y verificar el contenido en español e inglés **antes de su publicación como documento definitivo**, incluyendo condiciones particulares para California/EE.UU. y demás jurisdicciones donde se distribuya.
9. Mantener el acceso gratuito con anuncios, si ese es el modelo final, y evitar prometer que la suscripción proporciona nuevos motores, mejores resultados o servicios VPN de terceros.

Fuentes oficiales para verificar al momento de lanzar:
- [Google Play — Subscripciones](https://support.google.com/googleplay/android-developer/answer/9900533)
- [Google Play — ID de publicidad](https://support.google.com/googleplay/android-developer/answer/6048248)
- [Google Play — Datos del usuario](https://support.google.com/googleplay/android-developer/answer/10144311)
- [Centro de suscripciones de Google Play](https://play.google.com/store/account/subscriptions)

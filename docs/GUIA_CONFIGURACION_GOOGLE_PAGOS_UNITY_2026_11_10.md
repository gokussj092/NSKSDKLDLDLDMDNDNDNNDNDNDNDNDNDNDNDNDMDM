# SP-DECODE: configuración de Google, tienda, pagos y Unity

Fecha de revisión: 2026-11-10. Rama de trabajo: `feat/nuevas-integraciones`.
Referencia de implementación: `9772084`, `ca06a27` y `04147bb`.

Esta es la guía de continuidad para que otro chat acompañe al propietario al
obtener credenciales y activar cada integración. **No contiene credenciales
reales ni acredita un despliegue en el VPS.** Las consolas deben abrirse con
las cuentas del propietario; completar identidad, datos bancarios, fiscalidad
y aprobaciones requiere su intervención. No se crearon cuentas comerciales.

## 1. Qué existe y qué falta

| Parte | Implementado en la rama | Falta para usarla públicamente |
| --- | --- | --- |
| Web y perfil | `/account`, Google OAuth, foto, nombre visible y usuario único | Desplegar, configurar OAuth y probar un login real |
| Tienda | `/store`, pedidos, entrega de claves, panel `/admin/store` | Credenciales, precios, impuestos y pruebas de cada pasarela |
| API comercial | Bearer, IP pública fija, cuota diaria y vigencia | Configurar el producto y probar desde la IP compradora |
| Licencia Offline | Producto y emisión de código separados de API | Activación L2, certificado, cupos/recuperación y APK compatible |
| Android Online | Menú lateral y acceso web en APK externa | Perfil/login nativo y, para compras en Play, Billing correspondiente |
| Unity | Adaptador opt-in compilable, excluido de builds normales y Offline | IDs, red aprobada, CMP real, conectar el flujo y QA físico |

Las cuentas no son obligatorias para las funciones gratuitas. No modificar
descifradores, HPKE, Integrity, firma ni paquetes para configurar esta tienda.
No interpretar una prueba CI como una compra sandbox remota o un login real.
El estado detallado está en [la documentación de implementación](STORE_GOOGLE_PAYMENTS_2026_11_10.md).

## 2. Orden recomendado para el siguiente chat

1. Leer esta guía y verificar el código/CI actuales de la misma rama.
2. Revisar el VPS y preparar PostgreSQL, conservando las ventas apagadas.
3. Obtener las credenciales Google y validar inicio/cierre de sesión.
4. Definir precio, cuota, vigencia y destinos fiscales desde el panel.
5. Configurar **una pasarela a la vez** y completar sus pruebas sandbox.
6. Resolver `MP-01` antes de prometer compatibilidad con credenciales nuevas de Mercado Pago.
7. Preparar respaldo/restauración de PostgreSQL y revisar condiciones comerciales.
8. Cambiar a producción solo después de las pruebas; no activar Offline todavía.
9. Tratar Unity y la activación Offline como trabajos separados de desarrollo.

El entorno de pagos se elige globalmente con `SPDECODE_PAYMENTS_LIVE`; esta
versión no permite Stripe en producción y PayPal en sandbox simultáneamente
en la misma instancia. Para probar mientras existen clientes reales, usar un
despliegue de pruebas separado, con su propia BD, origen, claves y webhooks.
No inventar un dominio de staging como si ya estuviera provisionado.

## 3. Inventario de credenciales y dónde guardarlas

Los secretos de la web van exclusivamente en `/etc/spdecode/cloud.env` del
VPS. No pedir sus valores por chat, guardarlos en Git ni ponerlos en Android
o variables `NEXT_PUBLIC_*`. El documento registra nombres y estados.

| Variable / dato | Se obtiene de | Destino |
| --- | --- | --- |
| `GOOGLE_CLIENT_ID` | Cliente OAuth de tipo Web en Google Auth Platform | `cloud.env` |
| `GOOGLE_CLIENT_SECRET` | Mismo cliente OAuth | `cloud.env` |
| `STRIPE_SECRET_KEY` | API keys del entorno Stripe seleccionado | `cloud.env` |
| `STRIPE_WEBHOOK_SECRET` | Secreto `whsec_…` del endpoint Stripe | `cloud.env` |
| `PAYPAL_CLIENT_ID` | App REST Merchant, Sandbox o Live | `cloud.env` |
| `PAYPAL_CLIENT_SECRET` | Misma app REST PayPal | `cloud.env` |
| `PAYPAL_WEBHOOK_ID` | ID de la suscripción de webhook de esa app | `cloud.env` |
| `MERCADOPAGO_ACCESS_TOKEN` | Credenciales de la integración MP del entorno elegido | `cloud.env` |
| `MERCADOPAGO_WEBHOOK_SECRET` | Firma secreta de Webhooks, misma integración | `cloud.env` |
| `BETTER_AUTH_SECRET` | Generado por `spdecode commerce init` | `cloud.env` |
| `SPDECODE_SHOP_TOKEN_KEY` | Generado por el mismo comando | `cloud.env` |
| `SPDECODE_SHOP_DB_PASSWORD` | Contraseña administrativa PostgreSQL generada | `cloud.env` |
| `SPDECODE_SHOP_APP_PASSWORD` | Contraseña distinta del rol de aplicación | `cloud.env` |
| `SPDECODE_DATABASE_URL` | DSN privado generado, host `shop-db` | `cloud.env` |
| App Key y Ad Unit ID LevelPlay | Aplicación Android y unidad intersticial | Futura configuración Android; aún no hay variables conectadas |
| IDs/credenciales de la red Unity Ads | Dashboard Unity y enlace de red | Dashboard de mediación; secretos administrativos fuera del APK |

La API Key que compra el cliente **no** es la clave de Stripe ni un token de
Mercado Pago. Se genera después del pago y se muestra una sola vez en su
cuenta. Una licencia Offline tampoco es una API Key.

No rotar `SPDECODE_SHOP_TOKEN_KEY` durante la configuración: verifica claves
ya emitidas. No regenerar contraseñas de un volumen PostgreSQL existente
editando solo el archivo de entorno. `commerce init` conserva valores previos;
no es un mecanismo de rotación ni un restablecimiento de la tienda.

## 4. Preparación del VPS y aplicación de cambios

Antes de ejecutar, revisar la rama y los resultados CI. Esta guía no autoriza
por sí sola un merge a `main`, cobros ni publicación en Play. Usar los comandos
del proyecto; no sustituirlos por un Compose con otro nombre de stack.

```sh
spdecode status
spdecode backup
spdecode update all feat/nuevas-integraciones
spdecode commerce init
spdecode panel sync-routes
spdecode commerce status
spdecode status
```

`update all` actualiza también el worker; si se necesita actualizar solo web,
revisar `spdecode help` y el alcance antes de elegir el comando. `commerce init`
requiere la imagen web ya actualizada: genera secretos, inicia la BD privada,
aplica el esquema y recrea web. Para una tienda ya inicializada, tras actualizar
la imagen utilizar `spdecode commerce migrate`. No borrar el volumen para migrar.

**Respaldo:** `spdecode backup` guarda configuración y revisión de código;
actualmente **no incluye un dump de PostgreSQL**. Antes de ventas reales falta
preparar respaldo cifrado de la BD, copia fuera del VPS y restauración probada.
No afirmar que ese comando protege los pedidos por sí solo.

Editar los valores en el VPS con un editor privado, por ejemplo:

```sh
sudoedit /etc/spdecode/cloud.env
sudo chmod 600 /etc/spdecode/cloud.env
spdecode restart web
spdecode status
```

El archivo debe conservar su formato dotenv y una sola entrada por variable.
No pegarlo entero en el chat ni ejecutarlo con `source`. `restart web` utiliza
recreación del contenedor para cargar los cambios. Los orígenes deben coincidir
exactamente, sin barra final:

```dotenv
CLOUD_SITE_PUBLIC_ORIGIN=https://spdecode.xyz
CLOUD_API_PUBLIC_ORIGIN=https://api.spdecode.xyz
CLOUD_ADMIN_PUBLIC_ORIGIN=https://panel.spdecode.xyz
SPDECODE_ACCOUNTS_ENABLED=false
SPDECODE_STORE_ENABLED=false
SPDECODE_PAYMENTS_LIVE=false
SPDECODE_COMMERCIAL_API_ENABLED=false
SPDECODE_OFFLINE_LICENSE_READY=false
STRIPE_AUTOMATIC_TAX=false
```

Este bloque muestra estados iniciales; no sobrescribir una instalación activa
con él. `CLOUD_TRUST_PROXY=true` requiere el Nginx del proyecto, que reemplaza
`X-Real-IP`. PostgreSQL no necesita puerto público. Mantener los controles
existentes de acceso al panel y al API.

## 5. Google Auth: obtener Client ID y Client Secret

Consola: <https://console.cloud.google.com/auth/overview>.

1. Entrar con la cuenta que administrará SP-DECODE y seleccionar o crear un
   proyecto. La web necesita un cliente OAuth **Web application**.
2. En **Google Auth Platform → Branding**, completar nombre SP-DECODE, correo
   de soporte/contacto y dominio. Registrar la portada, privacidad y términos:
   `https://spdecode.xyz`, `https://spdecode.xyz/privacy` y
   `https://spdecode.xyz/terms`. Completar la verificación de dominio/marca que
   solicite la consola para ese proyecto.
3. En **Audience**, elegir la audiencia apropiada para usuarios externos.
   Si permanece en Testing, añadir las cuentas Google de prueba que corresponda.
4. En **Data Access**, limitar la identidad a `openid`, `email` y `profile`.
   No solicitar Gmail, Drive ni permisos de pagos para iniciar sesión.
5. En **Clients → Create client**, seleccionar Web application. Registrar el
   origen web si el formulario lo requiere y esta URI de redirección exacta:

   ```text
   https://spdecode.xyz/api/auth/callback/google
   ```

6. Copiar **Client ID** y **Client Secret** en el almacenamiento privado del
   propietario. Guardar el secreto cuando se muestre; no depender de poder
   volver a revelarlo en la consola.
7. Introducir ambos valores en `GOOGLE_CLIENT_ID` y `GOOGLE_CLIENT_SECRET` del
   VPS. Con la BD y `BETTER_AUTH_SECRET` preparados, poner
   `SPDECODE_ACCOUNTS_ENABLED=true`. Mantener `SPDECODE_STORE_ENABLED=false`.
8. Ejecutar `spdecode restart web` y probar `/account` desde el sitio público.
9. Para apertura pública, revisar Audience/Verification Center y completar
   los requisitos que Google muestre; Testing no equivale a acceso público.

**Diferencias del proyecto:** no usar el JSON de una service account de Play
Integrity como secreto OAuth. No reemplazar `CLOUD_GOOGLE_SERVICE_ACCOUNT_JSON`
ni el número del proyecto de Integrity. Este acceso web no necesita configurar
la huella de firma Android. El login nativo Android aún no está implementado.

**Prueba:** aceptar términos, entrar con una cuenta permitida, comprobar foto,
correo verificado y handle único; cambiar nombre/handle, cerrar sesión y volver
a entrar. Abrir dos cuentas e intentar el mismo handle debe producir un rechazo.
No presentar el inicio del flujo OAuth como prueba del callback real.

Fuentes: [Google Auth Platform](https://support.google.com/cloud/answer/15544987),
[OAuth Clients](https://support.google.com/cloud/answer/15549257),
[OpenID Connect](https://developers.google.com/identity/openid-connect/openid-connect),
[Better Auth Google](https://better-auth.com/docs/authentication/google).

## 6. Stripe: claves, webhook, wallets e impuestos

Dashboard: <https://dashboard.stripe.com/>.

1. Entrar con la cuenta comercial del propietario. Completar los requisitos
   que Stripe indique para recibir y liquidar pagos en México.
2. Seleccionar un sandbox/modo de prueba. En **API keys**, obtener la clave
   secreta de ese entorno para `STRIPE_SECRET_KEY`: `sk_test_…` o una clave
   restringida `rk_test_…` con los permisos realmente necesarios. La clave
   publicable `pk_test_…` no sustituye la secreta; este Checkout alojado no
   requiere copiarla al frontend.
3. En **Workbench → Webhooks → Create an event destination**, elegir eventos
   de la propia cuenta y formato **Snapshot**. El adaptador actual lee
   `event.data.object`; no configurar Thin como si ya fuera compatible.
4. Registrar este endpoint HTTPS y los cuatro eventos admitidos:

   ```text
   https://spdecode.xyz/api/store/webhooks/stripe

   checkout.session.completed
   checkout.session.async_payment_succeeded
   charge.refunded
   charge.dispute.created
   ```

5. Revelar el secreto de firma del endpoint (`whsec_…`) y guardarlo en
   `STRIPE_WEBHOOK_SECRET`. No confundirlo con una API key o el secreto de
   un listener temporal de Stripe CLI.
6. Elegir una versión Snapshot compatible con el SDK fijado y probarla.
   En `04147bb`, Stripe Node 23.1.0 declara `2026-10-28.endive` en
   `cloud/web/node_modules/stripe/esm/apiVersion.js`. Volver a comprobarlo si
   cambia el lockfile; no actualizar la versión de toda la cuenta a ciegas.
7. En ajustes de métodos de pago, solicitar/habilitar tarjetas y, cuando sean
   elegibles, Apple Pay, Google Pay, Link o métodos locales compatibles con
   Checkout. Su presencia depende de cuenta, moneda, país y dispositivo.
   No se necesitan otros secretos de Google OAuth para activar Google Pay.
8. Mantener `SPDECODE_PAYMENTS_LIVE=false` durante las pruebas. Al pasar a
   producción, sustituir **clave y secreto de webhook** por los de Live.

**Impuestos:** decidir entre tasas manuales revisadas y Stripe Tax. Para tasas
manuales positivas, crear en Stripe una tasa que corresponda a producto,
jurisdicción, porcentaje y comportamiento exclusivo, y copiar su ID `txr_…`
a la regla del panel. Con Stripe Tax, completar configuración y registros
fiscales aplicables antes de `STRIPE_AUTOMATIC_TAX=true`. El Checkout muestra
el impuesto definitivo; el webhook vuelve a comprobar los importes. Las reglas
de destinos del panel siguen siendo necesarias en esta versión.

**Prueba:** comprar desde `/store` con los datos de prueba oficiales de Stripe,
seguir el pedido en `/account`, verificar entrega única, repetir la notificación
y comprobar un reembolso. No usar datos de tarjeta real en la prueba. Un evento
simulado sin un pedido propio y una sesión de Checkout real no acredita el flujo.

Fuentes: [API keys](https://docs.stripe.com/keys),
[Webhooks y formatos](https://docs.stripe.com/webhooks),
[Métodos de pago](https://docs.stripe.com/payments/payment-methods/integration-options),
[Stripe Tax](https://docs.stripe.com/tax/checkout),
[Pruebas](https://docs.stripe.com/testing).

## 7. PayPal: app REST, Client ID, secreto y Webhook ID

Dashboard: <https://developer.paypal.com/dashboard/>.

1. Entrar con la cuenta del propietario. Preparar una cuenta **Business** para
   la integración comercial; completar los requisitos de recepción/retiro.
2. Abrir **Apps & Credentials → Sandbox** y crear o seleccionar una app REST
   de tipo **Merchant**, asociada al vendedor sandbox. No crear un producto
   de suscripciones: el código utiliza Orders v2 con captura.
3. Obtener Client ID y Client Secret de esa app. Guardarlos en
   `PAYPAL_CLIENT_ID` y `PAYPAL_CLIENT_SECRET`.
4. En los webhooks de la misma app Sandbox, registrar:

   ```text
   https://spdecode.xyz/api/store/webhooks/paypal

   PAYMENT.CAPTURE.COMPLETED
   PAYMENT.CAPTURE.REFUNDED
   CUSTOMER.DISPUTE.CREATED
   ```

5. Copiar el **Webhook ID** generado a `PAYPAL_WEBHOOK_ID`. Es el identificador
   de la suscripción, no el Client ID, un Event ID ni un secreto `whsec_`.
6. Preparar comprador sandbox distinto del vendedor y realizar una compra
   desde `/store`, manteniendo `SPDECODE_PAYMENTS_LIVE=false`.
7. Al volver a `/account`, el servidor captura la orden propia. La entrega
   espera el webhook verificado y la relectura de la orden PayPal.
8. Para producción, seleccionar **Live**, obtener las credenciales de la app
   Live y crear su webhook Live. Sustituir los tres valores conjuntamente.

**Prueba:** observar captura y entrega; repetir el webhook sin recibir otra
clave y probar reembolso. El simulador genérico PayPal no basta: su verificación
por el endpoint `verify-webhook-signature` no admite esos mock events. El
adaptador utiliza precisamente esa verificación remota; validar con transacción
sandbox real y notificaciones de la app. No retirar la verificación para que
el simulador aparezca en verde.

Fuentes: [Credenciales REST](https://developer.paypal.com/api/get-started/),
[Registro, verificación y simulador de webhooks](https://developer.paypal.com/api/rest/webhooks/rest/),
[Paso a Live](https://developer.paypal.com/api/rest/production/).

## 8. Mercado Pago: token, firma y compatibilidad que revisar

Portal: <https://www.mercadopago.com.mx/developers/panel/app>.

1. Entrar con la cuenta del vendedor y crear/seleccionar la integración de
   Checkout Pro. **Este código usa Preferences API** (`/checkout/preferences`),
   pagos `/v1/payments` y merchant orders; no es una integración Orders API.
2. En las credenciales de la integración, elegir el entorno de pruebas y
   obtener el **Access Token privado** para `MERCADOPAGO_ACCESS_TOKEN`.
   Public Key y Client ID/Client Secret no son sustitutos de ese token.
3. Antes de continuar, realizar la comprobación `MP-01` descrita abajo.
4. En **Webhooks → Configurar notificaciones**, registrar la URL de pruebas
   y seleccionar el tópico **Pagos / payment** que corresponde al adaptador:

   ```text
   https://spdecode.xyz/api/store/webhooks/mercadopago
   ```

5. Obtener la **firma secreta** de Webhooks y guardarla en
   `MERCADOPAGO_WEBHOOK_SECRET`. No es el Access Token. El código comprueba
   `x-signature`, `x-request-id` y el ID del pago antes de consultar su estado.
6. Probar una compra **MXN** con los recursos/cuentas/tarjetas de prueba que
   indique la documentación de la variante contratada. La integración actual
   no acepta USD/EUR para MP.
7. Verificar pago aprobado, entrega, repetición y reembolso. El evento debe
   corresponder a un pago real de prueba propio, no solo a un ID inventado.
8. Para producción, activar el entorno de producción y completar los datos
   comerciales solicitados. Copiar el token productivo y configurar la firma
   y URL de producción de esa integración antes de cambiar el modo global.

### MP-01: no deducir el entorno únicamente del prefijo

En `04147bb`, `providerConfigured()` de `cloud/web/lib/commerce/config.mjs`
exige `TEST-` cuando `SPDECODE_PAYMENTS_LIVE=false` y `APP_USR-` cuando es true.
La documentación actual de Mercado Pago indica que **Checkout Pro con Orders
puede entregar tokens de prueba `APP_USR`**. Esta diferencia se detectó al
preparar esta guía; no se ha validado una cuenta MP real.

El siguiente chat debe identificar la variante exacta de integración y los
recursos sandbox ofrecidos por esa cuenta. Si el token de prueba legítimo no
pasa la validación actual, documentar y corregir esa compatibilidad con pruebas
aisladas antes de abrir ventas. **No poner `SPDECODE_PAYMENTS_LIVE=true` ni
modificar el token para hacer pasar una prueba.** Tampoco aceptar notificaciones
`order` en un adaptador que espera `payment` sin implementar la migración.
Mantener la verificación de firma y de `live_mode` del pago consultado al PSP.

Fuentes: [Credenciales y entornos actuales](https://www.mercadopago.com.mx/developers/es/docs/your-integrations/credentials),
[Webhooks para Checkout Pro Preferences](https://www.mercadopago.com.mx/developers/es/docs/checkout-pro-preferences/additional-content/notifications/webhooks),
[API de Preferences](https://www.mercadopago.com.mx/developers/es/reference/online-payments/checkout-pro-preferences/get-preference/get).

## 9. Precios, API, impuestos y condiciones de venta

Entrar en `https://panel.spdecode.xyz/admin/store` con el acceso administrativo
existente; Google OAuth de clientes no reemplaza esa autenticación.

1. Configurar precios por moneda. USD/MXN/EUR son importes independientes;
   no existe conversión automática de precios. El producto API queda sin
   venta hasta definir precio, cuota diaria y vigencia.
2. El formulario expresa precios en unidades monetarias; el servidor guarda
   centavos enteros. La cuota API usa días UTC, y su vigencia comienza al
   revelar la primera clave. La IP pública se fija al comprar.
3. Definir las reglas fiscales que correspondan al negocio y destino. No
   copiar un IVA mexicano a todos los países. `rateBps=1600` significa 16%,
   pero no demuestra que esa tasa sea aplicable. `reviewed:true` requiere
   revisión efectiva del operador y sus obligaciones fiscales.
4. Estructura del editor de reglas: `country`, `region` (o `*`), `rateBps`,
   `label`, `reviewed` y `stripeTaxRate` opcional. Sin regla revisada para el
   destino, la compra se bloquea. Una tasa manual positiva de Stripe requiere
   además el ID `txr_…` correspondiente.
5. Usar el calculador de margen con las comisiones contratadas. La comisión
   del PSP, su IVA y los impuestos de la venta son conceptos diferentes.
   No se garantiza un neto exacto ante cambios, cambio de moneda o disputas.
6. Conservar un precio comercial común por producto y moneda. El acuerdo
   PayPal México revisado prohíbe recargos por elegir PayPal. Las tasas de
   comisión concretas deben consultarse en la cuenta del propietario.
7. Confirmar identidad comercial, soporte, privacidad, conservación de datos
   y condiciones de reembolso antes de abrir. El recibo actual no es CFDI.

Para pruebas sandbox de API, habilitar el producto, cuota y precio de prueba,
`SPDECODE_COMMERCIAL_API_ENABLED=true` y `SPDECODE_STORE_ENABLED=true` en la
instancia de pruebas con `SPDECODE_PAYMENTS_LIVE=false`. Mantener los demás
PSP sin configurar hasta que toque probarlos. No confundir esta habilitación
de prueba con autorización para cobros reales.

Para ventas API, probar desde la IP registrada
`https://api.spdecode.xyz/api/commercial/v1/decode`; otra IP debe ser rechazada.
Comprobar cuota, vencimiento, rotación y reembolso. No poner tokens de clientes
en ejemplos, historial de shell, capturas o incidencias públicas.

Fuente de la condición PayPal: [Acuerdo México](https://www.paypal.com/mx/legalhub/paypal/useragreement-full?locale.x=en_MX).
La configuración fiscal debe decidirse para el negocio real; no se prescribe
en esta guía una tasa universal ni un tratamiento fiscal particular.

## 10. Paso a producción y pausa de ventas

Completar primero las pruebas remotas de cada método que se vaya a ofrecer y
la restauración de BD. Mantener el sitio en pausa comercial durante el cambio.

1. Poner `SPDECODE_STORE_ENABLED=false` y aplicar `spdecode restart web`.
2. Guardar los secretos sandbox en el almacén privado del operador. Sustituir
   por credenciales **Live** de todos los PSP que se ofrecerán y sus secretos
   o IDs de webhook correspondientes. Retirar la configuración incompleta de
   métodos que aún no estén listos; no dejarlos anunciados como disponibles.
3. Configurar los webhooks Live del sitio y `SPDECODE_PAYMENTS_LIVE=true`.
   Aplicar `spdecode restart web` y revisar el estado del panel.
4. Revisar moneda, producto habilitado, reglas fiscales y destinatarios.
   Mantener `SPDECODE_OFFLINE_LICENSE_READY=false`.
5. Cuando esté aprobado el inicio de cobros, habilitar la tienda y verificar
   una compra real controlada, su liquidación/comisiones y posible reembolso.
   No ejecutar un cargo real sin la autorización correspondiente.

Los pedidos y permisos guardan el modo sandbox/Live. Las claves sandbox no
sirven al pasar a producción; no convertir filas de prueba en ventas reales
editando la BD. No cambiar otra vez la instancia productiva a sandbox para
probar: interrumpiría las claves Live y el procesamiento correcto de eventos.

Para pausar nuevas ventas, usar `SPDECODE_STORE_ENABLED=false` y recrear web.
Conservar los secretos Live y el modo Live: los webhooks de pedidos existentes
siguen siendo necesarios para pagos pendientes, reembolsos y disputas. Las
claves API ya emitidas tienen su control separado; no apagar ese servicio por
confundir una pausa de ventas con la revocación de todos los clientes.

## 11. Unity LevelPlay y Unity Ads: datos a obtener y trabajo pendiente

Esta parte no se activa escribiendo secretos en `cloud.env`. No existen aún
variables `UNITY_APP_KEY` ni `UNITY_AD_UNIT_ID` conectadas a la aplicación.

1. Crear/usar la organización Unity del propietario y completar sus datos de
   monetización, pagos y verificaciones solicitadas. Registrar **SP-DECODE
   Online Android**, con el package real `com.ghostdeveloper.spdecode`.
   Verificar la aceptación del modelo y canales de distribución, incluida
   APK externa si se va a monetizar fuera de Play.
2. Añadir la aplicación en LevelPlay y obtener su **App Key Android**.
   Crear una unidad **Interstitial** y obtener el **Ad Unit ID LevelPlay**.
   Esos dos identificadores se pasan al adaptador Android; no son los
   Client ID/Secret de Google ni la clave privada de una pasarela.
3. Configurar Unity Ads como red mediada. La guía oficial ofrece enlace
   automático o configuración manual de la red. Si se usa la manual, obtener
   Game ID Android y Placement/Ad Unit de Unity Ads y asignarlos en LevelPlay.
   No intercambiar el Game ID de la red con el App Key de LevelPlay. Secretos
   administrativos/de service account usados por el dashboard no van al APK.
4. Elegir e implementar un CMP real y aplicar consentimiento y preferencias
   de privacidad antes de inicializar/cargar anuncios. Completar los requisitos
   de privacidad de la app; no simular `cmpCompleted=true`.
5. Conectar `UnityInterstitialHost` al resultado persistido y al ciclo de vida
   de la actividad. El host actual exige consentimiento y limita frecuencia,
   pero **ninguna pantalla lo inicializa ni lo llama aún**. Falta además la
   conexión real del kill switch y su configuración.
6. Para compilar la variante de prueba del SDK, el proyecto utiliza
   `-PspdecodeUnityAds=true` con Cloud habilitado; no usarlo en Offline.
   Versiones preparadas: LevelPlay 9.7.0 y adapter Unity Ads 5.16.0. No instalar
   Unity Engine para esta app Android nativa.
7. Usar las herramientas/dispositivos de prueba oficiales de la red. Verificar
   consentimiento rechazado/retirado, no-fill, background, cierre y callback
   único. El resultado debe abrirse también cuando no haya anuncio. Conservar
   el límite acordado de 10 minutos/3 al día; no anunciar en errores, parciales,
   reaperturas o copia/exportación. No hacer clic en anuncios propios.
8. Después de QA físico y aprobaciones, preparar la distribución firmada.
   No ofrecer banners, Native o rewarded como integrados por obtener estos IDs.

Fuentes: [Añadir app](https://docs.unity.com/en-us/grow/levelplay/platform/get-started/add-app),
[Unidades](https://docs.unity.com/en-us/grow/levelplay/platform/get-started/ad-units),
[Red Unity Ads](https://docs.unity.com/en-us/grow/levelplay/sdk/android/networks/guides/unity-ads),
[Privacidad Android](https://docs.unity.com/en-us/grow/levelplay/sdk/android/regulation-advanced-settings).
Plan del proyecto: [Monetización Online](MONETIZACION_ANUNCIOS_SPDECODE_ONLINE_2026_11_09.md).

## 12. Licencia Offline: lo que no se resuelve con credenciales de pago

Dejar `SPDECODE_OFFLINE_LICENSE_READY=false`. La APK actual no consume los
códigos emitidos por la tienda. Para vender se requiere implementar y probar
activación L2, identidad/claves de dispositivo, certificado firmado, tres cupos,
recuperación y funcionamiento posterior sin red. La API Key y su clave HMAC
no sustituyen la clave de firma de activación; esta última todavía no tiene
un flujo de aprovisionamiento implementado en la tienda.

Consultar [plan de licencias y API](MONETIZACION_LICENCIAS_OFFLINE_API_IP_2026_11_09.md).
Una autorización permanente almacenada en un dispositivo desconectado no
puede revocarse instantáneamente; las condiciones no deben prometerlo.

## 13. Diagnóstico y pruebas de aceptación

| Síntoma | Revisar primero |
| --- | --- |
| Google deshabilitado | Flag de cuentas, BD, secreto Better Auth y ambos datos OAuth |
| `redirect_uri_mismatch` | URI exacta del cliente Web; origen/HTTPS y barra final |
| Google solo permite testers | Audience, publicación y estado de verificación del proyecto |
| `CSRF_REJECTED` | Acceder por el dominio oficial; origen exacto y proxy, no quitar el control |
| Panel tienda sin datos | `commerce init/migrate`, BD y credenciales de panel existentes |
| Pasarela no disponible | Credenciales completas, modo global y, para MP, `MP-01` |
| `TAX_NOT_CONFIGURED` | Destino revisado, regla y `txr_…` si Stripe manual con tasa positiva |
| Pago pendiente tras volver | Evento/entrega en el PSP, firma, estado de pago y pedido propio |
| Simulador PayPal rechazado | Limitación del mock con verificación remota; usar transacción sandbox |
| `PAYMENT_MODE_MISMATCH` | Entorno del pedido, credenciales y webhook; no editar el modo en la BD |
| `IP_NOT_ALLOWED` | IP de salida real compradora y cabecera impuesta por Nginx |
| API antigua deja de servir al rotarla | Comportamiento esperado; actualizar el cliente con la nueva clave |
| Clave sandbox no sirve en Live | Comportamiento esperado; no es una compra de producción |
| Unity no muestra nada | Host todavía no conectado, CMP, aprobación, IDs o disponibilidad de red |

Registrar por integración: modo, fecha, cuenta/aplicación identificada sin
secretos, resultado y evidencia de prueba. Ejemplo: «PayPal sandbox, webhook
verificado, entrega única y reembolso probados». No registrar claves completas.

Las pruebas necesarias incluyen: rechazo/cancelación sin entregar acceso,
importe/moneda y pedido correctos, pago pendiente, notificación repetida,
reembolso/disputa admitidos, rotación, IP/cuota y eliminación de cuenta.
La simulación CI no sustituye estos resultados. Verificar UI móvil/escritorio;
la vista previa administrada de la sesión de implementación falló antes de
arrancar por flags de Vite incompatibles con Next.js, por lo que esa QA visual
no se dio por completada.

## 14. Prompt breve para continuar en otro chat

> Continúa SP-DECODE en `feat/nuevas-integraciones`. Lee
> `docs/GUIA_CONFIGURACION_GOOGLE_PAGOS_UNITY_2026_11_10.md` y
> `docs/STORE_GOOGLE_PAYMENTS_2026_11_10.md`. Verifica el estado actual y guíame
> paso a paso para obtener/configurar Google OAuth, Stripe, PayPal y Mercado
> Pago en el VPS, una integración a la vez. Revisa MP-01 antes de configurar
> Mercado Pago. No me pidas secretos por chat: indícame dónde guardarlos.
> Prueba sandbox antes de Live y distingue configuración de desarrollo pendiente
> para Unity, login Android y activación Offline. No actives cobros ni publiques
> APK/AAB sin que se haya solicitado ese paso.

Mantener este documento actualizado con estados y pendientes, sin guardar
valores de credenciales. Las etiquetas de las consolas pueden cambiar;
comprobar los enlaces oficiales antes de guiar una sesión futura.

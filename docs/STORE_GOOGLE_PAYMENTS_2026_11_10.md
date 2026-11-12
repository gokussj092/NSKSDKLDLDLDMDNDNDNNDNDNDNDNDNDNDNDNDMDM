# Web, cuenta Google y tienda — 2026-11-10

Rama: `feat/nuevas-integraciones`. Implementación preparada para revisión;
**no desplegada ni habilitada para cobros reales**. Esta petición autoriza la
implementación de tienda que los planes anteriores dejaban aplazada.

Para obtener credenciales y configurar cada servicio, seguir la
[guía operativa y de continuidad](GUIA_CONFIGURACION_GOOGLE_PAGOS_UNITY_2026_11_10.md).
Incluye un hallazgo pendiente `MP-01` sobre prefijos de tokens de prueba de
Mercado Pago y la distinción entre Preferences API y Orders API.

## Experiencia

- Web pública AMOLED ES/EN: información de Online, Offline y API, tienda,
  preguntas frecuentes y acceso a cuenta en la cabecera. No exige iniciar
  sesión para usar gratuitamente la aplicación.
- Google es el único proveedor de login habilitable. Better Auth 1.7.20
  gestiona OAuth, estado, sesiones persistentes y cookies. No se habilitan
  contraseñas, OTP ni vinculación automática de identidades por correo.
- Perfil: nombre visible independiente del usuario único, normalización NFKC
  y minúsculas, reserva de nombres, unicidad en PostgreSQL y control de cambio
  de handle cada siete días. Las operaciones sensibles exigen sesión reciente.
- Cuenta: pedidos, comprobante comercial, permisos adquiridos, entrega de
  claves una sola vez, rotación API, exportación de datos y eliminación.
- Panel `/admin/store`: precios por moneda, cuota diaria y vigencia API,
  disponibilidad de productos, reglas fiscales revisadas y cálculo de margen
  estimado. Reutiliza la autenticación administrativa y sus controles CSRF.

## Productos y límites actuales

| Producto | Precio inicial | Permiso | Estado de venta inicial |
| --- | --- | --- | --- |
| Online | Gratis | Funciones actuales de la app | Sin cuenta obligatoria |
| Offline | US$4.99 según el plan aprobado | Licencia personal, 3 dispositivos | Deshabilitada |
| API por IP | Sin precio publicado | Una IP pública, cuota diaria y vigencia configurables | Deshabilitada |

Los precios se guardan en centavos enteros y por moneda; no se inventa una
conversión USD/MXN/EUR. Las claves API y los códigos Offline son independientes,
aleatorios de 256 bits y se guardan solo como verificadores HMAC. La primera
entrega de una API Key inicia su vigencia; rotarla no extiende el periodo.
El límite diario usa UTC. Los fallos del motor liberan la reserva de uso de
forma idempotente. Las reservas abandonadas se recuperan al siguiente uso.

**La activación Android Offline L2 no forma parte de esta tienda.** La APK
Offline actual no aplica estas licencias. Sus ventas requieren
`SPDECODE_OFFLINE_LICENSE_READY=true` solamente después de implementar y
probar la activación compatible. El panel por sí solo no sortea ese bloqueo.
No vender una clave como funcional en la APK actual.

La ruta comercial de archivos reutiliza el motor existente, sin modificar
descifradores: `/api/commercial/v1/decode`. Requiere bearer, permiso activo,
IP de origen exacta, cuota, límites de concurrencia compartidos y configuración
de proxy confiable. No acepta IPs privadas ni cabeceras de cliente arbitrarias:
Nginx reemplaza `X-Real-IP`. La IP se fija al comprar; su cambio administrativo
todavía no tiene una interfaz de autoservicio. No se anuncian suscripciones,
créditos de análisis ni renovaciones automáticas como habilitados.

## Pasarelas, total e impuestos

Stripe Checkout, PayPal Orders/Capture y Mercado Pago Checkout Pro usan páginas
alojadas por el proveedor. SP-DECODE no recibe números de tarjeta. Apple Pay,
Google Pay, Link y métodos locales se habilitan desde la cuenta del proveedor,
sujetos a moneda, país, dispositivo y aprobación; no se simulan como métodos
siempre disponibles. Mercado Pago se limita a MXN en esta integración.

Se respeta la decisión de precio configurable en el panel. El margen de
comisiones se incorpora a un **precio comercial común por producto y moneda**;
no se aplica un recargo específico por PayPal. El acuerdo de PayPal México
prohíbe ese recargo. El cálculo del panel estima el neto con las tasas
introducidas por el operador; no garantiza un neto exacto ante conversión,
comisiones internacionales, ajustes, reembolsos o contracargos.

Los impuestos de la venta son distintos de las comisiones del procesador.
No se aplica 16% de IVA indiscriminadamente. Cada destino necesita una regla
revisada por el operador. Con Stripe Tax, el total fiscal definitivo se calcula
y muestra en Checkout y se relee desde Stripe antes de entregar el permiso.
Se requieren registros fiscales activos en las jurisdicciones correspondientes.
Las reglas manuales de Stripe con tasa positiva necesitan un ID `txr_` válido.
PayPal y Mercado Pago usan el total fiscal cotizado por el servidor. La cuenta
de Stripe México puede requerir MXN para tarjetas nacionales: configurar precio
MXN y probar esa combinación antes de ofrecerla. El recibo de la web es un
comprobante comercial; no se presenta como CFDI ni factura fiscal automática.

## Confirmación y seguridad

1. El comprador autenticado elige producto, moneda, destino y método. El
   servidor toma precio y versión desde PostgreSQL y guarda el consentimiento.
2. El pedido usa idempotencia por comprador. Una concesión temporal impide
   crear enlaces en paralelo para el mismo pedido.
3. El proveedor crea el checkout con un identificador interno de pedido.
4. El retorno del navegador **no acredita el pago**. PayPal captura mediante
   servidor, pero la entrega espera el webhook verificado.
5. Stripe valida firma y antigüedad; PayPal confirma la firma mediante su API;
   Mercado Pago valida HMAC, tiempo y enlace de ID. Se relee el objeto de pago
   desde el proveedor y se compara pedido, moneda e importe.
6. Una transacción bloquea el pedido y registra un evento único. El permiso
   tiene unicidad por pedido. Repeticiones no entregan licencias adicionales.
7. Reembolsos y disputas admitidos revocan el permiso para futuros usos.
   Un evento de éxito atrasado no lo reactiva. La revocación instantánea de
   un certificado Offline permanente en un dispositivo desconectado no es posible.

Credenciales, HMAC de tokens y secretos OAuth son exclusivamente del servidor.
Los códigos completos no se guardan en registros ni en el navegador de forma
persistente. Las páginas/API de cuenta y compras usan `no-store`. La
eliminación borra la identidad de acceso, revoca permisos y limpia claves/IP;
se conservan referencias contables seudónimas según las obligaciones aplicables.
El despliegue comercial debe completar su política de retención, copia de
seguridad cifrada, restauración y requisitos fiscales antes de aceptar dinero.

## Preparación del VPS

Tras revisión de código y CI, usando los comandos reales del proyecto:

```sh
spdecode update all feat/nuevas-integraciones
spdecode commerce init
spdecode panel sync-routes
spdecode commerce status
spdecode status
```

`commerce init` crea secretos privados sin imprimirlos, arranca PostgreSQL 16
sin puerto público y aplica el esquema con los productos inicialmente apagados.
La aplicación usa un rol sin privilegios de superusuario. La configuración
existente no se rota ni se sobrescribe; `commerce migrate` conserva precios.
El esquema de cuentas anterior `001_identity_schema.sql` sigue siendo un
contrato histórico y no se aplica automáticamente a esta base nueva.

Configurar en `/etc/spdecode/cloud.env`, sin enviar secretos por chat ni Git:

| Integración | Variables / configuración |
| --- | --- |
| Google | `GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET`, `SPDECODE_ACCOUNTS_ENABLED=true` |
| Origen | `CLOUD_SITE_PUBLIC_ORIGIN=https://spdecode.xyz` |
| Stripe | `STRIPE_SECRET_KEY`, `STRIPE_WEBHOOK_SECRET`, `STRIPE_AUTOMATIC_TAX` según registros |
| PayPal | `PAYPAL_CLIENT_ID`, `PAYPAL_CLIENT_SECRET`, `PAYPAL_WEBHOOK_ID` |
| Mercado Pago | `MERCADOPAGO_ACCESS_TOKEN`, `MERCADOPAGO_WEBHOOK_SECRET` |
| Tienda | `SPDECODE_STORE_ENABLED`, inicialmente `false` |
| Modo | `SPDECODE_PAYMENTS_LIVE=false` para pruebas; no usar llaves Stripe live en ese modo |
| API comercial | `SPDECODE_COMMERCIAL_API_ENABLED`, inicialmente `false` |

URI Google: `https://spdecode.xyz/api/auth/callback/google`.
Webhooks: `https://spdecode.xyz/api/store/webhooks/stripe`, `/paypal` y
`/mercadopago`. Suscribir eventos de pago completado, reembolso y disputa
admitidos por cada adaptador. No mezclar cuentas sandbox/live ni webhook IDs. Cada pedido y permiso queda ligado
a su modo de pago. Las claves de prueba no autorizan la API al pasar a producción;
la web identifica las compras sandbox y el servidor rechaza entregas entre modos.
Aplicar cambios con `spdecode restart web`; verificar pago sandbox, repetición,
rechazo, impuesto, reembolso y entrega antes de activar producción. Ninguna
credencial comercial ni sesión Google real se utilizó durante el desarrollo.

## Android y Unity

El menú de Online abre con hamburguesa o gesto lateral. Ofrece acceso a la
cuenta web y, para APK externa, a la tienda. No inventa un perfil nativo ni
un usuario autenticado; la integración nativa de cuenta permanece pendiente.
Los accesos de compra/cuenta web están deshabilitados en la variante Play
hasta implementar el flujo nativo y Billing correspondiente. Offline no cambia.

Se prepara un adaptador aislado Unity LevelPlay 9.7.0 + Unity Ads adapter
5.16.0, opt-in con `-PspdecodeUnityAds=true`. Se excluye de las compilaciones
normales y de Offline. No instala Unity Engine. No se inicializa desde la APK
actual: faltan cuenta/red aprobada, App Key, Ad Unit, CMP real y validación en
dispositivo. El adaptador exige consentimiento previo, solo recibe datos
técnicos no sensibles, omite errores/parciales/no-fill/background, aplica
10 minutos/3 al día y continúa al resultado mediante un callback idempotente.
No se habilitan nativos, banners ni rewarded, ni se crean IDs de ads.txt.

## Validación y límites

- Regresión web local final: 715 pruebas, 712 aprobadas y 3 omitidas; build Next.js correcto.
  Python: 19 contratos de Android/VPS aprobados, además de la ruta Nginx comercial.
- SQL real mediante PGlite para desarrollo y PostgreSQL en CI: esquemas,
  nombres únicos, precios, idempotencia, entrega, cuota, IP, rotación y revocación.
- OAuth: inicio de flujo, estado y rechazo de callback ajeno; no se simula una
  sesión Google como si fuera una autenticación real del propietario.
- Build de Next.js y regresiones existentes; compilación Android y variante
  SDK opt-in se validan de forma independiente.
- CI del código `9772084`: [Store Google and Payment Contracts](https://github.com/gokussj092/NSKSDKLDLDLDMDNDNDNNDNDNDNDNDNDNDNDNDMDM/actions/runs/42880025927):
  11/11 contratos con PostgreSQL 16, incluida entrega y revelación concurrentes;
  regresiones y build web correctos; compilación Kotlin con Unity opt-in correcta.
  Ningún anuncio ni pago real se solicitó. El control F7-A1 previo que prohibía
  toda ruta de cuenta se actualiza a pruebas de configuración, modo y origen;
  las primitivas históricas de contraseña/OTP siguen deshabilitadas y verificadas.
- La vista previa administrada no pudo arrancar: inyecta `--host`/`--strictPort`,
  opciones de Vite que Next.js no acepta. No se modificó la aplicación para
  sortear ese fallo de infraestructura. QA visual en navegador queda pendiente.
- Webhooks/proveedores se prueban con datos ficticios. Pago real/sandbox remoto,
  callback Google real, Docker del VPS y pruebas físicas Android no están certificados.

## Fuentes oficiales revisadas

- https://better-auth.com/docs/authentication/google
- https://better-auth.com/docs/concepts/database
- https://developers.google.com/identity/openid-connect/openid-connect
- https://www.paypal.com/mx/legalhub/paypal/useragreement-full?locale.x=en_MX
- https://developer.paypal.com/studio/checkout/standard/integrate
- https://www.mercadopago.com.mx/developers/es/docs/checkout-pro-orders/notifications
- https://docs.stripe.com/checkout/fulfillment
- https://docs.stripe.com/tax/checkout
- https://support.stripe.com/questions/supported-payment-methods-in-mexico?locale=es-ES
- https://support.google.com/googleplay/android-developer/answer/10281818?hl=en
- https://docs.unity.com/en-us/grow/levelplay/sdk/android/changelog
- https://docs.unity.com/en-us/grow/levelplay/sdk/android/networks/guides/unity-ads

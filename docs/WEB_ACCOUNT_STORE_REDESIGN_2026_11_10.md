# SP-DECODE — Rediseño público de acceso, cuenta y tienda
Revisión: 2026-11-10. Rama: `feat/nuevas-integraciones`.

## Pantallas
- `/login`: pantalla propia Google OAuth, sin formularios de contraseña. Tras autenticación regresa a rutas internas permitidas.
- Menú hamburguesa en todas las secciones públicas: lateral izquierdo, abrir con botón o gesto desde borde izquierdo hacia derecha (también gesto desde extremo derecho hacia izquierda), cerrar con Escape, toque fuera o deslizamiento hacia izquierda. Navegación accesible y sensible a sesión. Sin login: Inicio, Funciones, Tienda, Soporte, Privacidad y Términos; con login: Mi perfil, Mis compras, Mis recibos, Mis productos, Cerrar sesión.
- `/account`: únicamente datos de perfil (nombre, usuario único, biografía, foto de perfil, correo Google de solo lectura), enlaces rápidos y privacidad/eliminación/exportación. Sin tablas completas de compras o licencias.
- `/orders`: pedidos e historial. `/receipts`: recibos comerciales de pagos confirmados (no CFDI). `/products`: claves y permisos, respetando revelación única, rotación API y vigencia.
- Retorno de PayPal: captura iniciada en la pantalla privada que recibe el callback y consulta el pedido hasta obtener confirmación; la redirección **no** se toma como prueba de pago.

## Almacenamiento de datos de perfil
`cloud/web/sql/002_shop.sql` añade `bio` y `avatar_data` de forma aditiva en `spdecode_shop.profiles`. Se actualiza por `PATCH /api/account/profile` tras sesión reciente y comprobación de origen. El servidor valida nombre, handle, biografía (máximo 180 caracteres) y avatar JPEG procesado en el navegador, 85 KB máximo, sin permitir SVG/URL externa ni acceder a archivos arbitrarios. Se conserva foto de Google como respaldo. El avatar se elimina junto con el usuario mediante FK cascade. No introducir secretos en clientes.

## Catálogo y planes
Productos existentes `offline-3` y `api-ip` mantienen su ID y campos previos. Opciones temporales adicionales en `settings.termPrices`:

```json
{
  "termPrices": {
    "1m": {"USD": 499},
    "2m": {},
    "3m": {},
    "6m": {},
    "12m": {}
  }
}
```

Los valores del ejemplo son **sintéticos de estructura**, NO una configuración comercial aplicada. Cada clave de moneda debe tener un precio real confirmado, expresado en centavos enteros. No completar automáticamente las claves vacías ni publicar tasas/cambios de divisa inventados.

`base` mantiene los planes históricos (Offline de pago único y API con `days` configurados). Un plazo `1m`, `2m`, `3m`, `6m`, `12m` equivale **contractualmente a 30, 60, 90, 180 o 360 días**, sin renovación automática. Mostrar esta precisión en el checkout. Para los planes extra, el panel `/admin/store` permite configurar precio por moneda y plazo; los descuentos solo se muestran cuando la comparación contra 1 mes efectivamente produce ahorro.

El servidor valida `term` y la moneda de la cotización. El checkout vuelve a obtener precio de PostgreSQL y utiliza término en huella de idempotencia y snapshot de pedido; el webhook sigue verificando importe, moneda y estado. Nunca se confía en precio del frontend. La vigencia de acceso API comienza cuando se revela la primera clave, igual que antes.

**Offline:** el código de emisión todavía no sustituye una APK Offline L2 con verificación fiable de caducidad. `SPDECODE_OFFLINE_LICENSE_READY` debe seguir `false` hasta implementar activación básica; el nuevo `SPDECODE_OFFLINE_TIMED_LICENSE_READY` también permanece `false` mientras no exista QA de licencias temporales. No activar ventas de un producto imposible de usar.

## Marcas de pago
Los símbolos SVG locales de Stripe, PayPal y Mercado Pago en `cloud/web/public/brands` proceden del catálogo de iconos de marca de Simple Icons, no son dibujos originales de SP-DECODE. Sus marcas pertenecen a las empresas correspondientes y se muestran junto con su nombre real. Respetar las pautas de cada proveedor antes de lanzar publicidad:
- Stripe: https://stripe.com/newsroom/information
- PayPal: https://newsroom.paypal-corp.com/media-resources?cat=3201
- Mercado Pago: https://www.mercadopago.com.mx/mp/logo-oficial

La disponibilidad real de pasarelas sigue determinada por `paymentReady`, país, moneda y entorno de pruebas/producción. No presentar un método como disponible si no cuenta con credenciales válidas.

## Despliegue seguro
1. Revisar flujo GitHub Actions `Store Google and Payment Contracts`; no desplegar si falla la compilación.
2. Respaldar VPS y, si hay pedidos reales, hacer dump PostgreSQL con recuperación probada. `spdecode backup` por sí solo **no** respalda datos PostgreSQL.
3. `spdecode update web feat/nuevas-integraciones` (actualiza fuente y reconstruye web; no reinicia worker deliberadamente).
4. `spdecode commerce migrate` (añade columnas de perfil), seguido de `spdecode restart web` si no se hizo recreación con el nuevo esquema.
5. `spdecode status` y pruebas reales en Android Chrome de menú, login/cerrar sesión, perfil, upload foto, pedidos, recibos, productos, cotización term + moneda y regreso de PayPal. Verificar además acceso sin login a `/store`.
6. Para los importes de los nuevos plazos, entrar a `https://panel.spdecode.xyz/admin/store` y configurarlos explícitamente. Los plazos sin precio siguen visibles para consulta, no para compra.
7. No activar pasarelas de producción ni licencias temporales antes de cumplir condiciones técnicas y fiscales.

## QA
Incluye `cloud/web/tests/store-terms.test.mjs` con pruebas sintéticas de importes por plazo, ubicación fiscal, entradas inválidas y bloqueo de Offline temporal. El workflow de GitHub compila Next.js, prueba el motor de pagos y verifica integración con PostgreSQL; las pruebas en dispositivos reales siguen pendientes de ejecución tras desplegar.

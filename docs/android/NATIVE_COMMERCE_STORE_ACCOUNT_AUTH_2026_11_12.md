# SP-DECODE Android — tienda, cuenta y acceso nativo (fundación UI)

Fecha: 2026-11-12. Rama: `feat/nuevas-integraciones`.
Implementación inicial: `NativeCommerceScreens.kt`, accesible desde `AccountDrawer.kt`.
**No** representa un lanzamiento de pagos, cuentas, licencias ni una aprobación de Google Play.

## Experiencia integrada en la APK

- Menú lateral: Tienda, Mi cuenta, Iniciar sesión (sin abrir navegador).
- Portada AMOLED coherente con SP-DECODE: créditos APK, API comercial, quitar anuncios.
- Fichas separadas, paquetes y cantidades, carrito local de demostración y
  subtotal. El checkout está **deshabilitado**: nunca cobrar a partir de
  importes definidos por el cliente, ni utilizar redirecciones de URL internas.
- Créditos APK: paquete de 1 (USD 3.99), 10 (USD 32.90) y 100 (USD 239.00).
  Valores solo **referenciales** mientras los precios oficiales no provengan
  del catálogo autoritativo del servidor.
- API comercial: 30 días USD 5.99, 90 días USD 15.49 y 360 días USD 49.99,
  importes referenciales; sin renovación automática implícita.
- Exclusivamente cuatro capacidades comerciales incluidas: descifrado de
  archivos, textos, métodos online y catálogo.
  **No** incluye análisis APK/APKS. No afirmar que existan métodos habilitados
  en la API sin verificación de disponibilidad desde el servidor.
- La IP pública de servidor es **obligatoria** para agregar la API al carrito.
  Validación local rechaza dominio, loopback, IP privada/reservada, multicast
  y literales malformados; admite IPv4 y IPv6 pública. Validación definitiva
  en `cloud/web/lib/commerce/config.mjs:publicIp` y
  `catalog.mjs:validatePurchase`. Vinculación de una IP a la licencia
  dentro del servidor existente (`api-ip`).
- Quitar anuncios: USD 1 por 30 días (referencia aprobada por el propietario).
  El producto aún **no existe** en `PRODUCT_IDS` del catálogo web: no
  activar dinero ni deshabilitar anuncios sin sincronización de entitlement
  y verificación de fecha de expiración del servidor.
- No aparece el producto de licencia Offline.

## Mi cuenta / inicio de sesión

- Pantallas nativas con estado invitado explícito, no simulan una sesión.
- Secciones: resumen de servicios, historial de compras/recibos,
  API (cuota/IP/rotación/revocación), seguridad y contraseñas.
- El acceso Google se presenta en un flujo de selección de identidad similar
  al de Unity, pero **aún no realiza OAuth real**.
  Para la fase siguiente, usar Credential Manager / Google Identity Services
  del lado Android con token de identidad validado en el backend por issuer,
  audience, nonce, expiración y usuario, sin WebView de credenciales, y
  una sesión móvil propia protegida por Android Keystore.
  La experiencia de perfil/tienda puede seguir siendo nativa; la
  autenticación de terceros no debe simularse con formularios locales.
- La API actual `cloud/web/lib/commerce/auth.mjs` tiene
  `emailAndPassword.enabled=false`. Por eso la UI de correo/contraseña
  está deshabilitada y el botón de agregar/cambiar contraseña informa que se
  necesita backend. **No guardar ni transmitir contraseñas ahora**.
  Para crear o vincular contraseña de una cuenta creada con Google:
  verificación de identidad reciente, prueba de control de correo,
  flujo de recuperación, protección anti-enumeración, límites de intentos
  y política explícita de vinculación para no duplicar identidades.
- No mostrar datos de perfil, órdenes, créditos, licencias o nombres de usuario
  inventados como si fueran del propietario.

## Requisitos para la fase de backend y publicación

1. Habilitar endpoint de catálogo móvil sin PII (ya existe GET
   `/api/store/catalog`) y representar únicamente planes reales y habilitados.
   Enlazar con cotización autorizada por versión, impuesto y moneda desde
   `/api/store/quote`, sin precios estáticos como autoridad.
2. Diseñar y activar sesión móvil segura conectada a las cuentas existentes;
   nunca enviar los secretos de Google o pagos al APK.
3. Implementar checkout autenticado, conciliación por webhook de pagos,
   recuperación de órdenes idempotente y actualización de créditos/API.
   Para Google Play usar el mecanismo de facturación aplicable a bienes y
   servicios digitales de acuerdo con sus políticas; no asumir que un
   checkout web externo está permitido en la AAB distribuida por Play.
4. Añadir producto `ad-free-30d`/entitlement server-side, compra y
   expiración 30 días; Unity LevelPlay debe consultar estado verificable
   para suprimir anuncios, incluso tras reinstalación/cambio de teléfono.
5. Añadir cuentas email/password solo después de un servicio de registro,
   correo verificado, restablecimiento y vinculación segura con Google.
6. Localizar esta primera UI en los otros idiomas; ahora los textos de
   la tienda tienen ES/EN y fallback en inglés.
7. Dispositivos reales: navegación Drawer/Tienda/Cuenta/Acceso,
   regreso Android, cuantías, control IP pública/privada IPv4/IPv6,
   rotación, controles disabled, responsive 320dp, contraste AMOLED.
8. Compilar firma persistente, revisar GitHub Actions, R8,
   Google Play Data Safety, consentimiento UMP y políticas de compras.

## No afecta

- Servidor VPS, descifradores, catálogos existentes, Play updater,
  publicidad real, sesiones previas ni entorno de pagos;
- Versión QA `1.1.27 / build 42` y clave de firma persistente.

# SP-DECODE · Carruseles AMOLED, créditos y mantenimiento

Fecha: 2026-11-10 · Rama `feat/nuevas-integraciones`.

## Estado de entrega y límites
Los cambios están en código; **no se despliegan solos a la VPS**. El login Google/Better Auth, las comprobaciones CSRF/origen, el rol privado `spdecode_shop_app`, los secretos protegidos y el proceso de pagos por webhook se conservan.

La UI de la tienda y checkout muestra el logo real local `/icon.svg`. No contiene títulos de demostración ni referencias a diseños/versiones de vista previa. El carrusel usa una tarjeta por página, salto circular, indicadores y teclado. En escritorio (>=800 px) muestra flechas **a los lados**, en móviles no hay flechas y se desliza la tarjeta. Los precios siempre provienen del catálogo de PostgreSQL y **no** del cliente.

### Tarifas USD aprobadas (centavos enteros)
| Paquete | Offline USD | API USD |
| --- | ---: | ---: |
| 1 mes (30 días) | 2.99 | 5.99 |
| 2 meses (60 días) | 5.49 | 10.99 |
| 3 meses (90 días) | 7.49 | 15.49 |
| 6 meses (180 días) | 12.99 | 27.99 |
| 12 meses (360 días) | 21.99 | 49.99 |

La API conserva su plan histórico `base`; Offline conserva el pago único `base`. Los nuevos términos se agregan **solo** cuando `termPrices` no existía, sin sobrescribir personalizaciones. Un año comercial aquí representa 360 días de servicio, no un año natural ni renovación automática.

| Crédito(s) | USD | Unitario USD |
| ---: | ---: | ---: |
| 1 | 3.99 | 3.99 |
| 5 | 17.95 | 3.59 |
| 10 | 32.90 | 3.29 |
| 25 | 74.75 | 2.99 |
| 50 | 134.50 | 2.69 |
| 100 | 239.00 | 2.39 |

Los seis paquetes se cargan con `enabled=false`. USD aparece inicialmente; **MXN/EUR quedan sin precio** hasta editarlos en `/admin/store`. No usar conversión implícita ni añadir recargos específicos por pasarela. Las tasas fiscales revisadas y el checkout siguen aplicando antes de cobrar.

## Seguridad de créditos
- Producto comercial `analysis-credits`; términos `1c`, `5c`, `10c`, `25c`, `50c`, `100c`.
- `credit_ledger` conserva asientos inmutables por cuenta, moneda de modo de pruebas/producción y origen de evento (compra, reembolso, gasto). El webhook de pago confirmado acredita una única vez, con restricción `UNIQUE(order_id,movement_kind)`; el retorno del navegador nunca acredita.
- Reembolsos y disputas revierten la totalidad del crédito otorgado. Si ya se consumieron créditos, el saldo puede ser negativo y bloquea nuevas reservas; no se regala crédito en contracargos.
- `credit_reservations` ofrece `reserveCredit`, `completeCredit`, `releaseCredit` con estado idempotente, bloqueo transaccional de cuenta y liberación ante fallo. Cada trabajo válido consume **un crédito solo si finaliza correctamente**.
- `/credits` es una pantalla privada para saldo; sin sesión muestra acceso Google.
- **No habilitar ventas de créditos ni usar reservas en producción** hasta que Android, el servidor y el trabajador generen un identificador de análisis confiable vinculado con la cuenta Google autorizada, implementen contabilización y reintentos, y completen QA de cobro/no cobro. Actualmente no hay puente de identidad a análisis APK.
- `SPDECODE_ANALYSIS_CREDITS_READY=false` es el bloqueo de seguridad por defecto (independiente de `enabled`, método de pago y `SPDECODE_STORE_ENABLED`).
- `SPDECODE_OFFLINE_TIMED_LICENSE_READY=false` mantiene bloqueadas licencias temporales Offline hasta que APK valide la expiración.

## Panel administrativo
- `/admin/store`: edición de plazos, créditos, precios USD/MXN/EUR, impuestos, estado del producto y visibilidad de pasarelas; validación transaccional en el servidor, versionado CAS, registro de auditoría.
- `/admin/cleanup`: política `cleanup-policy` con `enabled=false`, retención 168/336/720 horas, solicitud manual en cola, hora/estado de última ejecución. GET/POST validados con sesión administrativa Redis, encabezado de acción y CSRF.
- El mantenimiento **no concede a Next.js acceso a Docker**, no acepta comandos arbitrarios ni rutas de archivo del navegador. Solo una tarea root en VPS consulta esa política.
- `spdecode cleanup install-timer` instala voluntariamente el temporizador `spdecode-safe-cleanup.timer` cada ~15 minutos. La política sigue apagada hasta habilitarla en el panel. La limpieza automática ocurre como máximo cada 24 horas.
- El ejecutor sólo permite `docker builder prune --filter until=<168|336|720>h --force` para cachés de compilación **sin uso**; no toca imágenes, contenedores, volúmenes, logs, PostgreSQL, catálogos, secretos ni resultados APK. Se niega a ejecutar si ve otros contenedores activos no pertenecientes a `spdecode-`. Es un cache prune del Docker daemon del VPS, por lo que el panel revela explícitamente su alcance.
- APK QA ya dispone de una recolección propia dependiente de los estados del trabajo; **no** ejecutar un segundo recolector que borre trabajos pendientes o en revisión.

## Procedimiento VPS
1. Esperar el resultado `success` de `Store Google and Payment Contracts` en el SHA exacto de la rama.
2. `spdecode status`, `spdecode backup` y respaldo independiente PostgreSQL: `docker exec spdecode-shop-db-1 pg_dump -U spdecode_admin -d spdecode_shop -Fc > /root/spdecode-shop-$(date -u +%Y%m%d).dump`. Proteger el archivo con `chmod 600`.
3. `spdecode update web feat/nuevas-integraciones`.
4. `spdecode commerce migrate` (crea tabla de créditos, política de limpieza y añade precios sin sobrescribir ediciones).
5. `spdecode restart web`, `spdecode status`, `spdecode commerce status`.
6. Probar `/store` y `/login` sin cuenta, sesión con Google, `/account`, `/orders`, `/credits`, `/products`. Verificar carrusel móvil sin flechas y desktop con flechas laterales. Probar monedas y pantalla de impuestos.
7. Opcional: `spdecode cleanup install-timer`; luego habilitar/simular solicitud desde `/admin/cleanup`, y verificar con `spdecode cleanup status`. El comando `spdecode cleanup disable-timer` detiene el temporizador.
8. No activar pagos ni créditos hasta conectar proveedores, derechos de uso, QA de identidad y reglas fiscales aplicables.

## QA
El workflow verifica `npm test`, pruebas comerciales contra PostgreSQL real, `npm run build`, `python -m py_compile`, la CLI y pruebas de configuración. Se añadieron pruebas para pago idempotente de créditos, reversión y devolución sin cargo por fallo. El resultado del workflow y las pruebas reales del VPS son verificaciones distintas; no afirmar una implantación completa sin ambas.

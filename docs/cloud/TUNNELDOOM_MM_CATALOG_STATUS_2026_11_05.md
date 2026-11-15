# TunnelDOOM 4.3.2 / MM Tunnel — comprobación C8 (2026-11-05)

**Rama:** `feat/nuevas-integraciones`. **Ámbito:** Cloud/worker/panel.
No despliegue, APK/AAB ni fusión con main.

## Hallazgos verificables

- TunnelDOOM `com.tunneldoom.http`: el broker y la CLI usan el GET fijo
  `https://panel.tunneldoom.space/config.json`, constatado para build
  **430/4.3.0** el 26 de octubre (Version473, 387 servidores). El trabajo
  interrumpido de Work señaló **4.3.2** y que el host anterior ya no daba
  respuesta en aquel entorno. No se recuperó el APK/XAPK 432 ni una muestra
  remota verificada. **No está identificada una nueva URL válida.** No cambiar
  el proveedor a una URL adivinada ni declarar corregida la descarga.
- MM Tunnel `co.strongteam.marvsudp` build47: el POST legítimo
  `hash=xsandokUpdatex` a `https://strongteam.co/api/mmtunnel/` ya figura
  en el código actual. Work obtuvo respuesta real el 5 de noviembre. El
  catálogo cifrado 2.46 (822713 bytes, SHA256
  `d36899110cd6976e8e43935fdd6a0e19952f8a3f12716f8a36fd7642fecc6241`)
  está conservado en Library: `MM-Tunnel-remote-2.46.enc`.
  La verificación independiente previa registró 38 servidores, 557 redes,
  3399 campos protegidos y aproximadamente 87.63s para descifrado completo.
- MM **ya está conectado** al catálogo público, al broker y al worker. La
  disponibilidad de cada VPS depende de `CLOUD_API_ENABLED`,
  `CLOUD_SERVER_VPN_ENABLED`, el switch persistente `mm-tunnel` y su bandera
  de mantenimiento. Activar un switch no prueba descarga/descifrado en el VPS.

## Procedimiento operativo en el VPS

1. Verificar primero que está desplegada la rama correcta y que el servicio
   `web` usa la imagen nueva. En el directorio raíz del checkout con
   `cloud/compose.yaml`, inspeccionar sin mutaciones:

   ```sh
   docker compose -f cloud/compose.yaml exec -T web node scripts/catalog-provider-check.mjs
   ```

2. Solo si la configuración global de Cloud y Server VPN está habilitada, activar
   **exclusivamente MM Tunnel** y probar su descarga por el broker (el GET de
   TunnelDOOM se comprueba aparte):

   ```sh
   docker compose -f cloud/compose.yaml exec -T web node scripts/catalog-provider-check.mjs --enable-mm --probe --mm-only
   ```

3. Comprobar TunnelDOOM por separado, sin alterar sus controles:

   ```sh
   docker compose -f cloud/compose.yaml exec -T web node scripts/catalog-provider-check.mjs --probe --tunneldoom-only
   ```

Salida JSON sanitizada: `configured`, `enabled`, `maintenance`, y
`download.state`. Una respuesta `received_not_decoded` significa únicamente
que llegaron bytes cifrados; se informa tamaño y SHA256, sin contenido. Un
`failed` incorpora solo una categoría de error, nunca URL, tokens o datos de
VPN. Un `skipped_provider_disabled` indica que no hubo intento de red.

**Validación de descifrado completa** para MM: pasar el fichero real cifrado
al worker separado con el comando ya documentado en
`decoders/Python/apps/MM_Tunnel/TESTING.md`; validar todos los registros y
`isPartial:false`. El presupuesto de catálogo existente es 120s para
trabajo CPU y 135s en el gateway; las métricas del VPS decidirán si es suficiente.
No cambiar el presupuesto sin evidencia de un timeout real.

## TunnelDOOM: siguiente evidencia necesaria

Extraer el XAPK/APK **4.3.2/build432** original del trabajo de Work. Comprobar
paquete/certificado y `ConfigUpdateco.doInBackground` contra el método de
build430; verificar el origen nuevo mediante el APK, la respuesta HTTP real,
el esquema y la igualdad del JSON entero con referencia independiente.
Registrar scripts, hashes, dependencias y resultados bajo
`analysis/com.tunneldoom.http/432/` conforme a
`analysis/METHOD_EVIDENCE_POLICY.md`.

**Estado:** MM disponible en código y activable mediante el script; habilitación
de producción no ejecutada aquí. TunnelDOOM 4.3.2 **PENDING**. No se inventan
endpoints, tiempos ni catálogos.

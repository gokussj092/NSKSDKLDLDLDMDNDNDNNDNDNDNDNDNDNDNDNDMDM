# SP-DECODE Cloud — KSH, MKK Hyper y DTunnel Mod

> [Guía de futuras integraciones y versionado del catálogo y novedades](CATALOGS_UPDATE_RUNBOOK.md)

Estas rutas funcionan del lado del servidor; no es necesario modificar el APK.

## KSH VPN 1.3.2

- Catálogo: `ksh-vpn`, con el icono original enviado por el propietario.
- Descarga HTTPS fija y sin URL ingresada por el usuario.
- El trabajador ejecuta el método existente `decoders/Python/apps/KSH_VPN/ksh_vpn.py`.
- AES-GCM verificado antes de entregar el JSON completo. Se preserva todo el arreglo `servers`.

## MKK Hyper VPN 2.9.2

Antes, el broker descargaba exclusivamente `api_server.json`; el script admite
cuatro orígenes identificados como `servers`, `static`, `subscriptions` y
`legacy-subscriptions`. Ahora se consultan por separado, en paralelo y con
la misma validación estricta de DNS público, TLS, redirecciones y tamaño.

El resultado conserva cada documento descifrado como `sources[].data` y agrega
`records` por origen. Cuando alguna fuente falla, conserva explícitamente
`sources[].error`, `complete: false`, `isPartial: true` y
`PARTIAL_SOURCE_FAILURE`; nunca interpreta un fallo como un catálogo vacío.

No se siguen automáticamente URL arbitrarias incluidas dentro de los índices
de suscripción: esos índices se muestran completos, pero no se convierten en
descargas no autorizadas. El operador puede solicitar ampliar la lista de
destinos, previa validación de cada uno.

## DTunnel Mod 4.2.5

- El motor offline original está disponible en la allowlist del trabajador
  como `dtunnel-mod` y soporta catálogo cifrado y enlaces `vpn://`.
- **No se añadió un proveedor público auto-descargable.** El método del
  propietario exige un encabezado `dtunnel-token` con identificador de cuenta;
  no se inventa ni se incorpora al APK o al repositorio.
- El usuario confirmó el icono verde adjunto para la entrada pública `DTunnel Mod`.
  Su identificador es `dtunnel-mod` y el asset validado está en
  `cloud/web/public/server-vpn-icons/dtunnel-mod.png`.
- La tarjeta es visible en el catálogo **con `decodeEnabled: false`**, porque
  todavía faltan credenciales legítimas y un broker autenticado en la VPS.

## Confirmación del icono verde

El usuario confirmó expresamente que el icono verde adjunto corresponde a la
entrada de **DTunnel Mod**. Se incorpora con el nombre de catálogo `DTunnel Mod`
y el ID `dtunnel-mod`; no se modifica el descifrador original ni se crea una
identidad adicional de «Fastriver VPN» o «Tunnelmoth» basada solo en el texto
que aparece dentro del logotipo.

El catálogo pasa a la versión base 13 y admite configuraciones existentes de
la VPS con `CLOUD_SERVER_VPN_CATALOG_VERSION=11` o `12` sin retroceder la
versión efectiva. El test de la ruta del icono exige el digest SHA-256 del
PNG aprobado y que el botón remoto permanezca deshabilitado.

## Validación

La regresión `tests/test_cloud_server_vpn_new.py` genera datos cifrados
sintéticos y ejecuta los motores originales mediante el aislamiento real del
trabajador. Comprueba múltiples entradas por fuente, JSON completo, corrupción
GCM y errores parciales explícitos. C2 también ejecuta
`tests/test_ksh_vpn.py`, `tests/test_dtunnelmod.py` y
`tests/test_mkk_hyper.py`.

Las pruebas sintéticas no verifican la disponibilidad actual de los servidores
de terceros. Antes de anunciar compatibilidad de producción se necesita una
prueba end-to-end desde la VPS y, si algún endpoint falla, observar su código
sin revelar en logs datos descifrados ni credenciales.

## Actualización después de aprobar el CI

```bash
sudo spdecode backup
sudo spdecode update all feat/austroplus-vpn-13-0-1-decoders
sudo spdecode providers status
sudo spdecode status
```

Solo si los proveedores estuvieran deshabilitados, detener QA y seguir el
procedimiento documentado para `sudo spdecode providers enable`. No publicar
el PR ni reiniciar servicios antes de comprobar el resultado de GitHub Actions.

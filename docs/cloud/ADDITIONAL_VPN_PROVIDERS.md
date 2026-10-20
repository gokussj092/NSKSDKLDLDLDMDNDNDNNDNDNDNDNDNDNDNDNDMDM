# SP-DECODE Cloud — KSH, MKK Hyper y DTunnel Mod

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
- Hace falta proporcionar un mecanismo de credenciales privadas del VPS y
  confirmar el icono original del proveedor antes de habilitar su botón público.

## Identidad pendiente del icono verde

El archivo adjunto se denomina `Fastiver Vpn Pro_icon.png` y el propio
logotipo muestra `FASTRIVER VPN`, mientras que la petición lo asocia con
«Tunnelmoth» y el único script adicional es `dtunnelmod.py`.
Estas denominaciones **no se tratan como sinónimos**. El icono verde no se
publica con una identificación que podría ser incorrecta; hace falta confirmar
nombre y método correspondiente.

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

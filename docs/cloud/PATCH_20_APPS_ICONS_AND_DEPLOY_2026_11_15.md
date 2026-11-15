# Parche de 20 apps: iconos, despliegue y alcance real

Rama: `patch/20-apps`. Base revisada: `22adc3b21d4a754a4e257aed3faa65d70e673f02`.
Fecha: 2026-11-15. Esta revisión no despliega el VPS ni instala tokens reales.

## Cambios de este parche

- Incorporados los 19 PNG de `iconos-sp-decode-parche-20.zip`, conservando exactamente sus bytes: 15 archivos nuevos y 4 reemplazos. AC TUNNEL VPN ya tenía el icono número 20.
- Versión base de catálogo 85 → 86 para invalidar el catálogo anterior y sus hashes de iconos. Un override superior existente conserva su valor por el control monotónico.
- Docker Compose pasa `SPDECODE_FMT_VPN_GITHUB_TOKEN` y `SPDECODE_RH_TUNNEL_GITHUB_TOKEN` solamente a `web`, donde se descargan los catálogos. Los workers de descifrado y el laboratorio no reciben estos secretos.
- Las solicitudes de FMT/RH añaden `Bearer ` al token sin prefijo. Antes el broker mandaba el token solo, aunque los scripts originales utilizan Bearer.
- Prueba del broker con credenciales ficticias: destinos fijos, esquema correcto, rechazo sin red ante token ausente/vacío/con saltos de línea y ausencia del token en el catálogo público. DTunnel conserva su encabezado anterior sin prefijo.
- No se modifican los scripts originales ni se habilitan proveedores pendientes.

## Actualizar el VPS y configurar los dos secretos

Desde la terminal del VPS:

```bash
sudo spdecode backup
sudoedit /etc/spdecode/cloud.env
```

Añadir o reemplazar estas dos líneas, sin duplicarlas, usando tokens autorizados con lectura de los respectivos repositorios de catálogo. Pegar el token sin `Bearer`, sin comillas y sin espacios:

```dotenv
SPDECODE_FMT_VPN_GITHUB_TOKEN=PEGA_AQUI_EL_TOKEN_FMT
SPDECODE_RH_TUNNEL_GITHUB_TOKEN=PEGA_AQUI_EL_TOKEN_RH
```

Guardar el archivo y ejecutar:

```bash
sudo chmod 600 /etc/spdecode/cloud.env
sudo spdecode update all patch/20-apps
sudo spdecode status
```

`update all` recompila y actualiza web/API/panel y decoder-worker. El CLI ya incluye comprobaciones HPKE y reversión del código si falla el despliegue. No basta con añadir los tokens a GitHub Actions Secrets: el VPS lee su propio `/etc/spdecode/cloud.env`. El comando `spdecode config set` actual no admite estas dos claves; usar el editor indicado.

Comprobar la presencia efectiva dentro del contenedor, sin imprimir valores ni descargar datos de terceros:

```bash
sudo docker compose --project-name spdecode \
  --env-file /etc/spdecode/cloud.env \
  -f /opt/spdecode/repo/cloud/compose.yaml \
  exec -T web node --input-type=module -e '
import {suppliedProviderConfigured} from "./lib/supplied-integrations.mjs";
for (const id of ["fmt-vpn", "rh-tunnel-lite"]) {
  console.log(id + ": " + (suppliedProviderConfigured(id) ? "CONFIGURADO" : "FALTA TOKEN O ES INVALIDO"));
}'
```

Esta comprobación valida presencia/formato, no permisos de GitHub ni éxito de descarga. Los dos valores no se proporcionaron en este chat: su validez real queda pendiente de la configuración y prueba en el VPS. Después, descargar esos catálogos desde SP-DECODE para verificar autorización y descifrado reales.

## Inventario completo de las 20 aplicaciones

La lista viene de los 20 expedientes añadidos en el commit base. Hay 15 apps nuevas y 5 actualizaciones (AC, MNR, Royal, UT Loop y EUT). Tener un script de investigación no implica que cada vía ya esté conectada al cliente.

| # | Aplicación | Alcance conectado en esta rama | Límites relevantes |
|---|---|---|---|
| 1 | AC TUNNEL VPN | Catálogo; archivo `.actun`; texto `actunnelvpn://` | Actualización. Falta exportación real del teléfono para parte de las pruebas de archivos/texto. |
| 2 | Bee VPN | Catálogo; archivo `.bee` con discriminación respecto al formato histórico | Catálogo con campos sin resolver; archivos nuevos probados con muestras sintéticas. |
| 3 | CHN TUNNEL LITE | Catálogo; texto `chntunnellite://` | Los archivos genéricos `.js/.rj` no se autodetectan por extensión. |
| 4 | EUT VPN | Archivo `.eut`; texto `eut-payload://`; compatibilidad histórica conservada | Actualización. Catálogo remoto sin sesión oficial; pruebas del formato nuevo sintéticas. |
| 5 | FMT VPN | Catálogo con token autorizado | `.dtk` sigue asignado a ANY VPN; no anunciar archivos FMT. |
| 6 | HTTP Tweak | Catálogo de servidores y tweaks | Los lectores históricos `.ht/.htb` siguen presentes; el nuevo lector de archivos no está enlazado por el inventario. No anunciar nube ni `httptweak://`. |
| 7 | JK VPN | Catálogo; archivo `.hs` discriminado respecto a RH | Perfil local con Keystore no exportable; no anunciar texto propio. |
| 8 | Marvs V2Ray / RH Tunnel Secure | Catálogo; archivo `.bbtun` | Archivos probados con muestra sintética; no anunciar nube propia. |
| 9 | MinaProNet | Lector histórico `.mina` conservado | El nuevo script de archivos no tiene extensión enlazada; catálogo sin fuente activa; nube no validada. |
| 10 | MNR TUNNEL PLUS | Catálogo; archivo `.stp`; referencia cloud histórica `mnrtunneludp://` | Actualización. El expediente nuevo no probó una clave real de nube; omitir nube del anuncio. |
| 11 | MT KING NET | Sin nueva vía pública enlazada | Scripts y expediente presentes; sin solicitudes de broker ni extensión/prefijo en el inventario. |
| 12 | PPH GOOD VPN | Catálogo | No tiene extensión propia exportable ni texto propio que anunciar. |
| 13 | RH Tunnel Lite | Catálogo con token autorizado; `.hs`; `SabDev://` y `shanS://` | Archivo exportado real pendiente; texto probado con registros reales. |
| 14 | Royal Tunnel VPN | Catálogo; archivo `.roy` | Actualización. Nube por clave no validada ni anunciada como nueva vía pública. |
| 15 | TCx Tunnel Plus | Archivo `.tcx`; texto `tcxtunnelplus://` | Catálogo remoto caído; formato de archivos probado con vectores sintéticos. |
| 16 | TSC VPN Proxy | Sin nueva vía pública enlazada | Scripts y expediente presentes; sin solicitudes de broker ni extensión/prefijo en el inventario. |
| 17 | UT Loop Pro VPN | Lector interno del catálogo de reserva actualizado | No hay descarga pública habilitada ni formato exportable conectado. Los archivos sellados con Keystore siguen fuera de alcance. |
| 18 | VLX Tunnel VPN | Catálogo; lector histórico `.vlx` conservado | El lector nuevo de archivos no tiene extensión enlazada; no anunciar archivos nuevos. |
| 19 | WyrVPN | Archivo `.wyr`; texto `wyrvpn://` | Catálogo remoto sin broker autorizado; parte de la protección de archivos solo tiene evidencia sintética. |
| 20 | ZIVPN Tunnel | Catálogo; lector histórico `.ziv` conservado | El nuevo lector `.ziv` no está enlazado por el inventario; no anunciar la versión nueva de archivos. |

No hay una nueva vía de nube verificada que deba anunciarse en esta tanda. MT KING NET, TSC VPN Proxy y UT Loop no deben promocionarse como nuevas funciones disponibles al público. MinaProNet no tiene una nueva vía pública habilitada en este parche. La disponibilidad observada en expedientes de 2026-11-14/15 no sustituye una prueba actual contra cada proveedor.

## Validación de esta revisión

Resultados ejecutados en esta revisión:

- Iconos/broker/catálogo/textos/controles: 52/52 Node; suite MNR tras actualizar el hash esperado al PNG del ZIP: 13/13.
- Los 20 expedientes: 151/151 tests, ejecutados por separado en sus carpetas.
- Worker: 20 casos, 12 pasan y 8 se omiten por falta de muestras privadas; no equivale a 20 escenarios realmente ejecutados.
- Instalador: 24/24 pruebas.
- Suite web completa: 777 casos. La primera ejecución dio 769 correctos, 5 fallos y 3 omitidos; uno era el hash antiguo de MNR, ya corregido. Los otros 4 fallos se reprodujeron intactos sobre el commit base: navegación del panel, permiso biométrico en documentación y 2 pruebas de condiciones de tienda. Son problemas previos y esta revisión no los declara resueltos. Ejecución final tras el ajuste del icono: 770 correctos, 4 fallos previos y 3 omitidos (777 en total).
- Compose parseado: ambos tokens van a `web` y no a otros servicios.

La validación de broker usa red simulada y tokens ficticios; no afirma acceso real a FMT/RH. Los PNG se abren como PNG válidos y se comprueba su identidad byte por byte con el ZIP.

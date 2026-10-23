# SP-DECODE Cloud — Guía para ampliar Server VPN en otro chat

**Último lector, 2026-10-23: CREEB INJECTOR 38.0 (40)**, `apps/CREEB_INJECTOR/`:
`.creeb` DES/Java Properties y JSON v1 con varios perfiles. Contraseña/HWID
son validaciones posteriores, no entradas de cifrado. **10 pruebas enfocadas
y 10 regresiones AboWaged aprobadas**, cinco documentos sintéticos íntegros,
tres DES iguales a JDK y cinco al worker. Pendiente archivo real. C8 pasa a
**250**, C0 sigue **240**. **Catálogo no identificado**: UpdateAsync entrega
metadatos APK; no registrar esa URL como servidores ni crear una ficha.
Server VPN conserva **35 / 37** y sus switches. Ver ANALYSIS/TESTING y
`creeb_verify.py`, `dex_method.py`, oracle JDK y RESTORE.md. Sin despliegue,
APK, Android/diseño ni C11. El avance AboWaged de abajo es el último catálogo.

**Última incorporación, 2026-10-23: AboWaged VPN 1.0 (1)**,
`apps/AboWaged_VPN/`, proveedor fijo `abowaged-vpn`. Catálogo remoto principal
12 servidores / 257 ajustes v4.6.3 y selector adicional de 2 UDP; ambos cuerpos
completos igual a JDK, CLI HTTPS y worker aislado. Asset inicial 1/1 v1.0.
Catálogo mínimo **35 / 37 fichas**, PNG original 456508 bytes, controles y
versión persistente conservados. `.awg` añadido en C8/bot: efectivo **249**,
C0 sigue **240**. La contraseña `MyPass` es un bloqueo posterior al descifrado,
no se solicita al usuario para abrir el archivo. Dos perfiles sintéticos con y
sin bloqueo; pendiente exportación `.awg` real. **11 Python / 68 Node aprobadas**,
cuatro wrappers ARM64 iguales. Herramientas `abowaged_verify.py` y
`abowaged_native_oracle.py`, referencia JDK/generador y recuperación en Git.
Ver `ANALYSIS.md` / `TESTING.md` de la app. Sin despliegue, APK, diseño Android,
fusión ni C11 automáticos. No confundir la PublicKey de DNS con recipient NPVS.

**Preferencia de esta sesión (2026-10-22):** cuando el usuario adjunte únicamente
un APK/APKS, continuar automáticamente esta misma integración en la rama del
PR #96. Mantiene autorización para consultar y descargar los catálogos externos
de la aplicación. Solicita integración rápida con comprobaciones puntuales del
script y del enlace al servidor, sin ejecutar todas las suites. Esta instrucción
sustituye para este lote la indicación general de abrir un PR independiente;
no autoriza fusionar, desplegar o publicar APK/novedades automáticamente.

**Estado:** ampliación de catálogo autorizada para los APK/APKS aportados en este lote del PR #96.
**Alcance:** backend Cloud y módulos Python; no modificar el diseño Android ni el panel web.
**Excepción autorizada por el usuario (2026-10-19):** ajustar exclusivamente carga,
muestreo y caché Android de iconos para que su peso no excluya aplicaciones.

## Organización por aplicación

Conservar una carpeta por aplicación bajo `decoders/Python/apps/<APP_NAME>/`, reutilizando nombres existentes.

- `file_decoder.py` para archivos exportados, únicamente si existe ese formato.
- `server_catalog_decoder.py` para el catálogo remoto, únicamente cuando se dispone de uno.
- `README.md` con app, versiones analizadas, extensiones, dependencias y limitaciones.
- `TESTING.md` con pruebas sin valores privados, casos satisfactorios y fallidos.
- `manifest.json` con ID estable, tipo de motor y versión compatible.

Los módulos pueden mantener los nombres actuales del repositorio. No duplicar motores históricos.

## Integración Cloud existente

1. Mantener una función `run(data: bytes) -> str` para un decodificador autónomo y reproducible.
2. Registrar cada extensión aplicable en el inventario y router Python, preservando formatos anteriores.
3. Registrar el decodificador de servidores en `cloud/workers/python/catalog_vpn_bridge.py`, por ID fijo.
4. Incorporar el proveedor validado en `cloud/web/lib/server-vpn-provider.mjs`.
5. Publicar únicamente metadatos en `cloud/web/lib/server-vpn-catalog.mjs`.
6. Colocar el icono PNG original autorizado en `cloud/web/public/server-vpn-icons/` y registrar su checksum.
   Todos los iconos originales se conservan aunque superen 256 KiB u otro umbral
   anterior. El peso no justifica omitir una imagen ni sustituirla por otra marca.
   Si el endpoint no está validado, conservar su ficha e icono con descifrado
   desactivado. Android verifica/cacha el original y muestrea solo la vista previa;
   se mantiene el presupuesto general del transporte, sin un filtro por app.
7. Añadir pruebas de paridad de los resultados JSON completos, validación, límites y manejo de errores.
8. Actualizar la versión del catálogo de forma monotónica al introducir nuevos proveedores.

El nombre y el icono se muestran en un único catálogo Android existente. No incluir en el APK métodos de descifrado, datos del proveedor ni información interna del backend.

## Entrega obligatoria

- Identificar versión y formato de cada muestra autorizada y documentar qué se comprobó.
- Los archivos con contraseñas/HWID se prueban con autorización y datos de prueba; no incluir información real en PR o CI.
- El adaptador de descarga nunca aceptará una ubicación arbitraria proporcionada por la aplicación.
- La interfaz pública no expondrá información interna de la API ni detalles operativos del servidor.
- Todas las pruebas automatizadas deben terminar correctamente antes de habilitar un método.
- Abrir PR independiente, sin fusionar a main, desplegar ni publicar APK sin autorización.
- Adjuntar listado de archivos creados, rutas del backend actualizadas y compatibilidad confirmada.

## Instrucción reutilizable para un nuevo chat

> Trabaja en el repositorio Gh0stDeveloper/SP-DECODE, en la rama de trabajo indicada. Analiza el APK y ejemplos que te proporcionaré y para los que cuento con autorización. Dentro de decoders/Python/apps crea o reutiliza una única carpeta por aplicación. Extrae por separado el decodificador de archivos y el del catálogo de servidores, si existen. Integra las rutas Python y los metadatos del catálogo en el backend Cloud, con pruebas reales de paridad y el icono original autorizado. No modifiques el diseño Android ni la web administrativa; en Android solo se autoriza la política general de carga/caché de iconos descrita en esta guía. No registres información sensible en archivos publicados. Deja el trabajo en un PR sin fusionar y documenta los pendientes.

## Pendientes hasta el próximo análisis

- Métodos de nuevos servidores y catálogos: pendientes de incorporación y pruebas.
- Habilitación pública de los proveedores: pendiente de verificación individual.
- Revisión jurídica de marcas, iconos y tratamiento de datos: `docs/cloud/LEGAL_PRELAUNCH_REVIEW_PENDING.md`.
- Mantener intactos los métodos y catálogos ya operativos durante la fase VII.

## Actualización del cliente para la política de iconos

El backend y el cliente actualizado aceptan los originales por encima de los
antiguos límites de 256 KiB / 350000 caracteres Base64. La caché utiliza el
presupuesto general de respuesta HTTPS (6 MiB); la imagen de visualización se
muestrea hasta 512 píxeles por lado sin reescribir el PNG original. Se mantienen
firma PNG, checksum, cifrado de caché y validación de dimensiones positivas.

Antes de activar en producción un catálogo con imágenes grandes, instalar en
los clientes una APK compilada con esta política. Una APK anterior no cambia
por actualizar solo el backend y puede rechazar el icono grande. No publicar ni
desplegar automáticamente como parte del análisis de una nueva aplicación.


## Herramientas conservadas y recuperación

Las herramientas reutilizables de este lote están versionadas en
`scripts/apk_analysis/`. `RESTORE.md` explica cómo recuperar el checkout,
recrear el entorno e instalar JADX con sus checksums cuando se pierdan los
datos temporales. Las referencias independientes y fixtures sintéticos de
7NET están en `tests/golden/sevennet*`; `sevennet_verify.py` compara el JSON
completo con JDK y opcionalmente con primitivas ARM64 y el worker aislado.
Conservar allí cualquier herramienta nueva; no depender solo del entorno.
APK/SO, inventarios de cadenas, catálogos reales y credenciales descifradas
permanecen fuera de Git. Último catálogo completo integrado: **7NET VPN 5.6**,
proveedor fijo `7net-vpn`. Último avance: **AM TUNNEL LITE VPN build 63**, aún
pendiente de abrir su catálogo LIAPP; ficha desactivada, catálogo mínimo
**34 / 36 fichas**. Revisar su `ANALYSIS.md` y no confundir el auxiliar de campos
ni la extracción de primera capa nativa con un catálogo completo.
Se recuperaron además 213 bytes de metadatos LIAPP y la identidad local
paquete/SHA-1. `am_liapp_metadata.py`, `am_liapp_native_probe.py` y los vectores
`tests/golden/am_liapp*` están conservados. El probe usa contexto/archivos
modelados; DEX original, lector exterior y respuesta remota siguen pendientes.

Último lector de archivos incorporado: **1FTunnel 0.6.99 (125)**,
`decoders/Python/apps/OneFTunnel/`. `.1ftnl` y cuatro prefijos, muestra real
completa igual a JDK y worker, **9 Python / 13 Node aprobadas**, 32 KDF ARM64.
Catálogo no identificado, pendiente; no añade ficha ni cambia Server VPN/C11.
C8 efectivo **248**; C0 congelado **240**. Herramientas `oneftunnel_verify.py`
y `oneftunnel_native_oracle.py` conservadas, instrucciones en RESTORE.md y
ANALYSIS.md. AM queda pendiente por indicación del usuario; no continuarlo
como parte del análisis 1FTunnel. Sin despliegue, fusión o APK automáticos.

Actualización posterior **NPV Tunnel 124.0.37**: `npvs.py` conserva v5 app-key
y añade passphrase v5 real completo; **16 Python / 15 Node aprobadas**.
Recipient v6 pendiente de privada; Rjo normal/public-key son el mismo adjunto.
La nueva muestra Kurdo normal v5 app-key 2 ya se abre sin contraseña/public key,
20 registros y 12 campos npvs1, JSON completo igual a JDK/worker. El script
`apps/NPV_Tunnel/text_decoder.py` se entrega separado para integración de textos
en otro chat por instrucción del usuario; no registrar todavía en routers.
Ver `docs/NPV_TEXT_AND_NORMAL_FILE.md`: cinco pruebas nuevas, solo npvt-ssh
confirmado como exportación del APK, cuatro aliases pendientes de enlaces reales.
No repetir la extracción de tablas: SO/rt.dat coinciden con el handoff anterior.
`go_inspect.py`, `npvs_verify.py` y referencias JDK/generador guardados.
Ver `docs/NPVS_PROTECTED_FILES.md`; no anunciar public-key como descifrado,
no modificar APK/UI ni volver a AM dentro de esta actualización.

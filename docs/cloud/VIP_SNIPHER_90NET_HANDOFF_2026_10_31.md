# VIP Snipher Pro y 90NET: estado y recuperación

Fecha: 2026-10-31. Repo Goku
`gokussj092/NSKSDKLDLDLDMDNDNDNNDNDNDNDNDNDNDNDNDMDM`.
Rama `fix/http-jireh-current-method`, sobre Netcol `9d5c778e`.
`main` no fusionó esta rama al iniciar; se continúa aquí. Mantener **59** por
la instrucción expresa del propietario para el lote aún no actualizado en VPS.
No desplegar, fusionar, generar APK ni lanzar Actions; commit `[skip ci]`.

## VIP Snipher Pro: lector offline verificado

Paquete `dev.renz.soft.vipsnipherpro`, **2.9 / 29**, obtenido de APKPure. Firma
binaria y versión comprobadas; lector en `decoders/Python/apps/VIP_Snipher_Pro/`.
Catálogo real incluido **3.0.22 / 14 servidores / 280 redes**, **2441 campos**,
1750 no vacíos. JSON completo igual a JCA, Python, CLI y worker aislado. Ocho
casos de primitivas ARM64 originales, sin JNI/Android. Gateway interno recibe
el resultado real completo con transporte simulado; `isPartial:false`.

Métodos: modo0 AES128CBC/XXTEA/restar2, modo1 Threefish256 con tweak siempre
(0,0)/AES128CBC, modo2 PBKDF2/XXTEA/AES256CBC con IV prefijado. Se preservan
todos los campos y estructuras; dos bordes de ceros Threefish comprobados.
No MAC; no presentar padding/JSON como autenticación criptográfica.

**Bloqueo remoto real:** URL fija del build termina en
`Civ3snipher/NEW-VIP-SNIPHER-PRO-3/refs/heads/main/update.json?ref=main`,
HTTP404 desde este entorno. URL histórica sin `-3` y API pública de ese repo
también404. No se afirma caída global del servicio. No reemplazarla por otra
fuente sin evidencia. Ficha e icono originales con `remote:null`; no hay broker
público ni switch de descarga para una fuente no validada. Worker offline sí
registrado. **53 fichas / revisión fuente59**, C0 240 / C8 254 /28 overrides.
Rutas `.vipsnipherpro` y `vipsnipherpro://` históricas intactas, sin certificación
de un export de build29. No registrar `.js/.rj` genéricos.

**51 Python /150 Node aprobadas**, sin skips, con regresiones del lote anterior
y metadata254 intacta. Comandos, hashes y límites en README/TESTING/manifest de
la app. Original PNG512×512 exacto en ficha y carpeta, sin conversión.

## Original duradero y reproducción

Original guardado y finalizado correctamente:
**VIP-Snipher-Pro-2.9-build29.xapk**, ID
**`libfile_fb815e6716cc81918ad90bc29bfbd9b6`**.
SHA256 **0738801b6fffa10afd01c4b61f091e193dfd976b322a37b5cf7a891821663f44**,
59683358 bytes. Contiene base, ARM64 y splits de idiomas/densidad.

Tras limpieza, recuperar el checkout actual de la rama y materializar ese
original. No confiar en que `latest` mantenga el build. Extraer
`dev.renz.soft.vipsnipherpro.apk` y `config.arm64_v8a.apk` con zipfile; de ellos
`res/aa/d.js`, `res/i/cb.png` y `lib/arm64-v8a/libovpn3.so`.
Verificar los hashes del manifest antes de analizar. Recrear dependencias de
`scripts/apk_analysis/requirements.txt`, app requirements y JDK.

`vip_snipher_verify.py asset --native libovpn3.so --runtime` compara todo el
JSON e imprime solo métricas/hashes. Oracles y vectores en
`tests/golden/vip_snipher*`. `decompile.py`, `elf_inspect.py`, `arm64_function.py`
y `paranoid_strings.py` conservan el análisis. LSParanoid de este build:
clase `defpackage/sl.java`, `--chunk-field a --method a --call-class sl`.
Los originales, strings e investigación temporal no se suben a Git.

## 90NET VPN: bloqueado por ausencia de entrada verificable

Paquete confirmado por ficha Google Play: **`com.ninetynetvpn.org`**, nombre
**90NET VPN**, desarrollador MO GROUPE. La ficha consultada indica actualización
2026-07-29; fuentes secundarias anuncian3.0/build30. **No se verificó ese build
mediante APK ni se recuperó su método**. No asumir que usa el mismo método de
MNR/AboWaged por compartir desarrollador.

Intentos de adquisición en esta sesión:

- APKPure descarga normal XAPK y APK: HTTP404; páginas `.net/.com`:410.
- APKCombo página y ruta de descarga:503 en este entorno.
- PGYER y APKsos, rutas exactas del paquete:404.
- APKFab:403; Aptoide app/get:404, búsqueda pública sin resultados.
- Sitio del desarrollador `https://90netvpn.blogspot.com/`:200, sin posts ni
  enlace a un binario. Canal público `https://t.me/s/ninetynetvpn`: página de
  sitio no disponible desde este entorno. No se contactó a ninguna persona.
- Búsquedas web por paquete/nombre y búsqueda Library por90NET/ninetynet no
  localizaron un APK verificable. No se han creado cuentas ni usado cookies,
  endpoints privados o credenciales ajenas.

**Para continuar hace falta un APK/XAPK verificable de esa app o un enlace
público directo vigente.** Entonces comprobar paquete/versión/firma y seguir
el flujo normal de análisis y paridad. No hay ficha, icono, motor ni proveedor
inventado de90NET en esta entrega. Estos pendientes no quedan completados por
el simple hecho de conservar esta documentación.

## Revisión final de VIP, 2026-11-01

Sobre `a8b16501` de la misma rama, sin modificar main ni desplegar. Google Play
sigue anunciando **2.9** en el HTML consultado de nuevo; APKPure lista
**2.9 /29** como último build. Se recuperó el original guardado, se verificaron
los hashes y se resolvieron de nuevo **1824 literales /71 fuentes**.

`VIPSNIPHERPROMain.s.getHeaders()` envía `Accept: application/json`,
`X-GitHub-Api-Version: 2022-11-28` y una autorización del desarrollador.
**No hay User-Agent propio en ese método. No reutilizar ni publicar la
autorización encontrada en el APK.** La herramienta incorpora exclusivamente
las cabeceras públicas. Su agente `VIP Snipher Pro/2.9` es un identificador
de herramienta, no un valor extraído de Android.

Pruebas anónimas con agente por defecto, de herramienta y Dalvik: todas404.
Este resultado no describe la petición autenticada original ni prueba caída
global. `remote:null` permanece; el lector offline y el worker sí funcionan.
Para cerrar la descarga automática falta una fuente accesible autorizada y
un catálogo real completo contrastado. No sustituirla por el asset antiguo.

Validación final: **8 Python /4 Node**, sin skips, más el documento original
completo **14 servidores /280 redes** con igualdad Java/Python/worker/CLI y
**8 casos nativos**. Catálogo59 y53 fichas intactos. 90NET queda expresamente
para después por instrucción del usuario.

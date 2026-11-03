# VIP Snipher Pro y 90NET: estado y recuperación

Actualizado: **2026-11-01**. Repo Goku
`gokussj092/NSKSDKLDLDLDMDNDNDNNDNDNDNDNDNDNDNDNDMDM`.
Rama `fix/http-jireh-current-method`, sobre `2c7a56c4`.
Mantener **59** para el lote aún sin desplegar, por instrucción del propietario.
No fusionar main, desplegar, generar APK ni lanzar Actions; commit `[skip ci]`.

## VIP: fuente autenticada y catálogo completo validados

Paquete `dev.renz.soft.vipsnipherpro`, **2.9 /29**. Google Play consultado de
nuevo anuncia 2.9; APKPure también lista 2.9/29 como último build.
Lector en `decoders/Python/apps/VIP_Snipher_Pro/`.

La URL exacta de `VIPSNIPHERPROMain.P()` es:
`https://raw.githubusercontent.com/Civ3snipher/NEW-VIP-SNIPHER-PRO-3/refs/heads/main/update.json?ref=main`.

`s.getHeaders()` declara `Accept: application/json`,
`X-GitHub-Api-Version: 2022-11-28` y `Authorization`; no declara un
User-Agent propio. Las pruebas anteriores sin autorización devolvían 404.
**La petición con la credencial del mismo APK devolvió HTTP200**, sin
redirección, usando únicamente esa fuente. No se probaron otros endpoints.

Catálogo remoto **8.0.61 /47 servidores /273 redes**, **323244 bytes**,
**2829 campos /1974 no vacíos** (1546 modo0,368 modo1,60 modo2).
SHA256 **1d68e41fedfd42dead2f6a1285c39494108ca9fe2f949578dd1cda2470aa49e5**.
Documento completo igual a Java independiente, Python, CLI y worker aislado;
**6 casos nativos ARM64** remotos iguales. CLI stdout 221911 bytes.
El resultado real completo pasa `fetchWorker` con HTTP interno simulado,
`isPartial:false`,47/273. No se afirma egress Node real ni sesión Android.

El asset incluido sigue **3.0.22 /14 servidores /280 redes**,
2441 campos/1750 no vacíos, con 8 casos nativos previos y dos bordes Threefish.
No sustituir el catálogo remoto por el asset antiguo.

Métodos: modo0 AES128CBC/XXTEA/restar2; modo1 Threefish256 con tweak siempre
(0,0)/AES128CBC; modo2 PBKDF2/XXTEA/AES256CBC con IV prefijado.
Preservar campos, listas y tipos; no hay MAC. El JNI completo no se ejecutó.

## Backend y validación de integración

El broker `vip-snipher-pro` ya está registrado con la misma URL y cabeceras.
La cabecera completa se suministra mediante
`SPDECODE_VIP_SNIPHER_AUTHORIZATION` como secreto de backend. Compose la
transmite solo a web. No se ha guardado su valor en Git ni se ha desplegado.
Al desplegar el lote 59 debe provisionarse desde la cabecera del original APK
guardado. No poner su valor en argumentos de comandos, logs o fixtures.

El proveedor requiere el secreto válido, switch global y disponibilidad
individual. Sin secreto queda deshabilitado antes de DNS; el panel puede
desactivarlo manteniendo los demás switches. Se rechazan DNS privados y todas
las redirecciones para que la autorización no salga de la URL fija. El secreto
no se envía a otros proveedores ni al worker ni se devuelve al cliente.

**11 Python /99 Node aprobadas, sin skips**, incluidas 8 Node específicas VIP.
Las pruebas de red Node utilizan mocks y credenciales ficticias. GET real
autenticado y paridad del catálogo remoto real verificados aparte.
Catálogo fuente **59 /53 fichas**; C0 240 /C8 254 /28 overrides intactos.
Rutas históricas `.vipsnipherpro`/`vipsnipherpro://` conservadas.
No hay certificación de un perfil exportado de build29 ni nuevas rutas .js/.rj.
PNG512×512 original exacto en ficha y carpeta, sin conversión.

## Originales duraderos y reproducción

Original APK/XAPK:
**VIP-Snipher-Pro-2.9-build29.xapk**,
ID **`libfile_fb815e6716cc81918ad90bc29bfbd9b6`**,
59683358 bytes, SHA256
**0738801b6fffa10afd01c4b61f091e193dfd976b322a37b5cf7a891821663f44**.

Catálogo remoto cifrado descargado:
**updater-authenticated.enc**,
ID **`libfile_4ba67f90a4188191b2017f22d42df8ce`**,
323244 bytes, SHA256
**1d68e41fedfd42dead2f6a1285c39494108ca9fe2f949578dd1cda2470aa49e5**.
No se ha guardado una copia descifrada duradera ni publicado entradas reales.

Tras limpieza, recuperar el checkout actual de la rama y esos originales.
No confiar en `latest` para mantener el build. Del XAPK extraer
`dev.renz.soft.vipsnipherpro.apk` y `config.arm64_v8a.apk`; de ellos,
`res/aa/d.js`, `res/i/cb.png` y `lib/arm64-v8a/libovpn3.so`.
Verificar hashes del manifest antes de analizar. Recrear requirements del
lector/análisis y JDK.

`vip_snipher_verify.py catalogo.enc --native libovpn3.so --runtime` compara
todo el JSON e imprime solo métricas/hashes. Oracles y vectores sintéticos en
`tests/golden/vip_snipher*`. Para recuperar la cabecera exacta sin publicarla,
JADX fijado y `paranoid_strings.py` resuelven
`defpackage/sl.java`, `--chunk-field a --method a --call-class sl`.
Usar en memoria la cabecera de `VIPSNIPHERPROMain.s.getHeaders()` solo para la
fuente fija. Los originales y fuentes resueltas contienen secretos: no subirlos
a Git ni imprimir la cabecera.

## 90NET VPN: pospuesto expresamente

El usuario pidió dejarlo para después; no se hicieron nuevos intentos.

## 90NET VPN: bloqueado por ausencia de entrada verificable

Paquete confirmado por ficha Google Play: **`com.ninetynetvpn.org`**, nombre
**90NET VPN**, desarrollador MO GROUPE. La ficha consultada indica actualización
2026-07-29; fuentes secundarias anuncian3.0/build30. **No se verificó ese build
mediante APK ni se recuperó su método**. No asumir que usa el mismo método de
MNR/AboWaged por compartir desarrollador.

Intentos anteriores de adquisición:

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

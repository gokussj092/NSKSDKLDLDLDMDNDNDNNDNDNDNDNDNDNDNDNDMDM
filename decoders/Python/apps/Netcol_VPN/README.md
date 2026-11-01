# Netcol VPN 14.2 (142)

Paquete **`com.netcol.vpn`**, desarrollador Pamcol DM. APK **14.2 / build 142**
obtenido de APKPure el 2026-10-31, confirmado por manifiesto binario y firma
SHA-1 `782749d51dc4c29b560d51b032b98490c287f988`, coincidente con el espejo.
Esta incorporación mantiene la revisión pública **59**, por instrucción del
propietario: aún no se ha actualizado ese lote en el servidor.

## Uso

Python 3.10 o posterior y `pip install -r requirements.txt`:

```bash
python server_catalog_decoder.py > servidores.json
python server_catalog_decoder.py copia_cifrada.txt > servidores.json
python server_catalog_decoder.py --stdin < copia_cifrada.txt
```

Sin argumentos descarga la única fuente fija comprobada. Archivo/stdin no usan
red. Mantener la carpeta hermana `HTTP_FenixVPN/` con `codec.py` y
`field_names.json`, que aporta la validación JSON y límites comunes. No se
requiere APK, root, contraseña del usuario, HWID ni claves personales.

No se identificó un formato propio de archivo exportado o un esquema de
enlace en las rutas analizadas. Se incorpora únicamente el catálogo; no se
registran `.netcol`, JSON genérico ni un lector de archivos por inferencia.
El inventario de archivos sigue en **240 C0 / 254 efectivos / 28 overrides C8**.

## Fuente activa y recuperación

El actualizador `p263o00ooo00.OooO0OO.OooO0O0` espera el resultado de
`C8162OooOo0O.OooOOo0`, que consulta Firebase Remote Config. La entrada
**`NEW_URL_UPDATE`** devolvió HTTP 200 con:

`https://raw.githubusercontent.com/jdavidag/setting/main/tO6oD1drTvL2.json`

La consulta se reprodujo con los metadatos públicos SDK extraídos del APK,
su paquete/certificado y un identificador anónimo de prueba; no necesitó
cuentas ni tokens de un usuario. `scripts/apk_analysis/netcol_source.py`
permite repetirla con el APK fijado por hash, sin imprimir API keys.
El contexto de prueba fue 14.2/build 142, idioma es, país CO y Android 35.

La fuente de respaldo ensamblada en el APK,
`https://raw.githubusercontent.com/jdavidag/update/main/Config`, devolvió
solo **un byte de salto de línea**. No se utiliza ni se intenta como fallback.
El campo literal `https://bitbin.it/o5lqHROL/raw/` tampoco es la URL empleada
por ese GET: este usa el resultado de la devolución de llamada.

El lector/broker fija la URL activa observada; **no consulta Firebase por cada
petición ni acepta URLs del cliente**. Una futura migración de Remote Config
requiere verificar y actualizar esa constante. El auxiliar de análisis solo
informa del cambio, no modifica el broker ni descarga un destino descubierto.

La descarga Python usa 25 segundos, HTTPS, 8 MiB, HTTP 200, contenido sin
compresión y ninguna redirección. El broker Node fija una IPv4 pública y
rechaza también redirecciones al origen anterior. El agente
`Netcol VPN/14.2` funcionó en el GET real.

## Método del catálogo y campos

`p263o00ooo00.OooO00o.OooO0o` convierte pares de símbolos del alfabeto
**`▙▚▛▜▝▞▟▃▄▅▆▇█▉▊▐`** en bytes del texto Base64. Tras Base64, descifra
AES-256-CBC/PKCS7 con IV cero. La clave es
**SHA256(hexadecimal mayúsculo de los bytes UTF-8 de `FamiliaGelves24`)**.
No es SHA256 directo de la contraseña. El método `AbstractC8167OooO0o0.OooO00o`
concatena `Fami` + `liaG` + `elv` + `es24` desde cuatro constantes del APK.

`NetColMainActivity` aplica una segunda capa solo a siete campos:

| Campos | Receta |
| --- | --- |
| ServerIP, ProxyIP, Payload, SNI, Slowchave, Nameserver | Base64 → Blowfish-CBC/PKCS5, clave UTF-8 `UniversalPro24`, IV `abcdefgh` |
| ServerUser | La misma primitiva, clave UTF-8 `LiamSebas18`, mismo IV |

La primera clave se ensambla desde `Uni` + `vers` + `alP` + `ro24` en
`p263o00ooo00.OooOOOO.OooO0Oo`; la segunda concatena `Inflater.S`, `Inflate.C`
e `InfBlocks.K` (`Liam`, `Seb`, `as18`). Estas clases de constantes se leyeron
en el DEX aunque JADX no reconstruyera sus clases anónimas. Los consumidores
son `p259o00ooOoO.OooOOOO.OooO00o` y
`p245o00oo0Oo.OooO0OO.OooO0O0`, respectivamente.

**ServerPass queda tal como viene**, al igual que puertos, Slowdns, InfoS,
banderas y campos desconocidos. Los indicadores originales mezclan booleanos
y cadenas `true`/`false`; no se fuerzan sus tipos. Se conserva el documento
entero. Los campos vacíos opcionales siguen vacíos; un error de padding,
alfabeto, UTF-8 o estructura rechaza el documento. El formato original usa CBC
sin MAC: validar padding/JSON no añade autenticación que el APK no tiene.

## Comprobaciones e integración

- Assets `assets/config/config.json` y `default_config.json`: iguales byte a
  byte, versión **0**, **2 servidores** y **14 campos cifrados** por copia.
- Fuente activa: versión **162**, **172 servidores**, **1204 campos cifrados**.
- Documentos completos iguales entre JCA independiente, Python y worker real
  aislado; `isPartial=false`. CLI real y gateway con la respuesta completa del
  worker comprobados, este último mediante transporte interno simulado.
- **43 pruebas Python y 146 Node aprobadas**, sin skips. Incluyen regresiones
  Wolf/Jireh/JyFast, inventario, controles, DNS privado y rechazo de redirecciones.

ID fijo `netcol-vpn`, tarjeta, icono y control individual. El catálogo conserva
**59** y pasa a **52 tarjetas**. Se mantienen las rutas existentes compartidas
por V1/V2 y los switches persistentes. No se compila Android ni se cambia el
inventario de formatos de archivos.

El launcher original `res/mipmap-xxxhdpi-v4/ic_launcher.webp` se conserva
intacto como `Netcol_VPN.webp`; el PNG público es una conversión de **192×192**
verificada con los mismos píxeles. Ver hashes y comandos en `TESTING.md` y
`manifest.json`. No se ejecutó la app original ni una conexión VPN, transporte
Node real al proveedor, suite completa o despliegue VPS.

El XAPK original está guardado persistentemente como
`Netcol-VPN-14.2-build142.xapk`, Library ID
`libfile_e75eaf1858108191be9bc2e88a598ec2`. La recuperación tras limpieza se
explica en `docs/cloud/NETCOL_VPN_HANDOFF_2026_10_31.md`. Git solo contiene
código, documentación, iconos y vectores sintéticos; las configuraciones reales,
credenciales, APK y respuesta completa de Firebase quedan fuera.

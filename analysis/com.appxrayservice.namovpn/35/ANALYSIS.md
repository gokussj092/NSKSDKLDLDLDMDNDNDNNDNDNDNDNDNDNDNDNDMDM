# Investigación de NAMO VPN 3.5-namo /35

Trabajo iniciado desde main45db1d4 en la rama nueva `feat/nuevas-integraciones`,
por instrucción expresa del propietario tras fusionarse el lote anterior.
Alcance: catálogo Cloud y descarga real autorizada. Sin Android, merge o VPS.

## Identidad y adquisición

Google Play identifica NAMO VPN, paquete `com.appxrayservice.namovpn`. La página
actual de APKPure ofreció3.5-namo/code35 y dos variantes ARM64. Se descargó
la variante sv24. El inspector confirmó paquete, nombre y versión en el APK.
XAPK33084055bytes y base8046628bytes; hashes en MANIFEST. El certificado DER
tiene SHA2564543ca61…72222d y SHA1 coincide con104ac2e6…453e76 publicado por el
mirror para versiones anteriores. Se inventarió presencia de firmas V2/V3;
no se verificó criptográficamente toda la firma ni equivalencia oficial Play.

## Observación y recuperación

1. `prepare.py` desempaqueta las APK raíz, inspecciona la base de nombre exacto
   y conserva assets/SO offline. No encontró catálogo precargado en assets;
   `v2ray_config.json` es un template, no sustituto de la descarga real.
2. JADX1.5.6, modo simple/no-res/j4, termina3 con40 errores. La ruta relevante
   está disponible. No se ejecuta código Android ni se considera reconstruida
   toda la app por tener fuentes parciales.
3. Strings LSParanoid fusionadas por R8 en `defpackage/lz1.java`, campo `b`,
   método `q`. El script compartido resuelve890 literales/49 fuentes e inventaría
   937 cadenas; los cuerpos aritméticos coinciden con el algoritmo compartido.
4. `MainActivity.A()` construye cliente OkHttp y request GET desde
   `MainDetail.a()`. `e2` inicializa GET; `vd` añade `okhttp/5.3.2` si falta
   User-Agent. No hay Authorization, parámetros de cuenta ni pasos de atestación
   en este updater. La clave de descifrado nunca se envía como header.
5. `libapi-namo.so` ARM64 tiene4312bytes. Dos getters JNI de20bytes devuelven
   cstrings: `a`0x6b8→0x4f0 es URL pública fija raw GitHub; `b`0x6cc→0x541 es
   constante de formato10bytes. Se leen ELF/rodata con pyelftools/Capstone,
   sin ejecutar SO, JNI ni verificaciones de licencia.
6. Callback `bd.b()` consume body y llama `kd0.run()`. Este abre el sobre con
   `j44.m(iz1.b(body), MainDetail.b().getBytes(UTF8))`, crea JSONObject y lee
   Version/Message. `so0.a()` abre la copia local igual y transforma nombres para
   la UI; nuestro resultado conserva el JSON original completo, sin esa
   normalización destructiva ni defaults artificiales.

## Método y confirmación

`j44.m/n` es XXTEA con **delta772515655**, enteros32bits little endian,
clave truncada/rellenada16bytes, última palabra como longitud; entrada Base64.
No es delta estándar0x9e3779b9 ni requiere el desplazamiento UTF16 de ZiG.
El interior viene en texto. No aplicar heurísticas de recifrado o extracción
de URI a Servers/Networks. `CatalogOracle.java` transcribe las dos direcciones
independientemente de Python. El verificador real recibe la clave del SO fijado
por hash, la coteja con la constante inline y compara todo el documento.

GET original con agente5.3.2: HTTP200,72881bytes, text/plain UTF8. Java abre
**22.3 /14 Servers /13 Networks**, con Version, Message, setOpenVPN preservados.
Python, CLI y child worker dan el mismo objeto entero. Segunda descarga desde
el adaptador operativo confirma bytes y resultado. Hashes/conteos en generated.

El propietario pidió incluir las claves en código para no perderlas. La
constante es exclusivamente del formato local y se incorpora en `codec.py`;
`set_format_constant.py` reproduce ese paso desde el SO fijado. No hay secretos
externos, cuentas ni credenciales de autorización nuevas. La documentación no
publica registros VPN reales ni valores de sus usuarios/contraseñas.

## Negativos y límites

- El primer extractor de icono eligió `XAPK/icon.png`, pero sus bytes son JPEG.
  Falló la validación PNG, sin fabricar ni recodificar branding. Se conserva
  el script v1 y se extrae finalmente el launcher PNG192×192 original de la base.
- Primer pase Node:139/140, test nuevo conservaba URL de plantilla con nombre
  cambiado. Se corrigió la expectativa al updater comprobado; producción y
  descarga real ya usaban la URL correcta. Pase final140/140.
- Transporte Node real: `REMOTE_NETWORK_DENIED`, distinto del GET Python200.
  Replay real bytes/worker con HTTP simulado pasa. VPS real queda pendiente.
- No se probaron conexiones VPN, cuentas, importación, exportación o perfiles;
  no se añaden formatos por tener un template. XXTEA no es autenticado: el esquema
  rechaza corrupción detectada, no promete integridad universal.

Expediente, scripts propios usados, versiones/dependencias y fixtures ficticios
se guardan en Git. La aprobación automática Fase7 y el bloqueo CI de evidencia
siguen pendientes de código; el método se prepara para revisión humana en PR.

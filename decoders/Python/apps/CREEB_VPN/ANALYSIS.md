# Reinvestigación CREEB VPN vigente50.0/build50 — 2026-11-01

Se leyeron la guía obligatoria de paridad, el inventario de catálogos pendientes,
runbook y documentación previa. El HTML actual obtenido directamente de Google
Play declara50.0; no se encontró una versión posterior confirmada. Los índices
de mirrors muestran versiones antiguas: latest XAPK/APK devolvió404 y su página
410. Se descargó de nuevo el original aportado anteriormente, conservado de
forma privada, **no una descarga nueva desde Play**. Su versión coincide con
la ficha vigente; hashes APKS/base/DEX coinciden exactamente con la tabla previa.
Original persistente: CREEB VPN_50.0.apks. Paquete com.creebtunnel.vpn, code50.
Certificado SHA256
`3d2426b63c3c16f825c71c7835339a560b10c4a06363ebc5895c546758182b8f`,
SHA1 `64e5dfb4e0dc46aecf33c88fcf2bda3540cfbde8`.
JADX1.5.6 otra vez con52 errores; métodos de red contrastados con Dalvik.

## Diferencia recuperada: preflight antes de Integrity

La documentación anterior omitía el GET previo. La secuencia activa arranca en
MainActivity.e0 y comprueba que Google Play Store está disponible/habilitado.
Después crea mv0(context,sh0.a,callback,eventId), donde sh0.a es exactamente
`https://app.creebnet.com/api/app-update-manifest`.

1. `mv0.doInBackground`,182 instrucciones: GET al mismo endpoint, Accept
   application/json, User-Agent CREEB-VPN-Android,15s conexión/lectura.
   Espera JSON con digest SHA256 hexadecimal y bypassActive opcional.
2. `bw.e` devuelve el DATA cifrado original de system.db/MagicPh_table.
   El digest compara SHA256 de sus bytesUTF8, no del JSON descifrado. Digest
   inválido o caché ausente conduce a solicitar Integrity; digest igual termina
   como sin actualización. Si difiere y el servidor indica bypassActive=true,
   la app tiene una rama oficial de POST sin token. No se fuerza ese flag.
3. `mv0.onPostExecute`,245 instrucciones: según el resultado anterior, inicia
   Play Integrity clásico con nonce16 bytes SecureRandom/Base64URL sin padding.
   `nv0.d` y `jv0` conservan exactamente el par token/nonce obtenido. Los errores
   transitorios -3/-8/-12/-17/-100 tienen hasta4 intentos, esperas5/10/20s;
   cada nuevo intento vuelve a generar nonce. Sin token la app también envía
   su rama de diagnóstico de fallo, no una atestación aceptada.
4. `lv0.doInBackground`,185 instrucciones: POST JSON UTF8 al mismo endpoint,
   Content-Type application/json; charset=utf-8, Accept text/plain, application/json,
   */*, User-Agent CREEB-VPN-Android,60s conexión/lectura. No se identificó otra
   Authorization/API key/cookie en esta ruta. No es un POST de formulario.

Cuerpo: integrityToken,nonce,packageName,diagnostics. Diagnostics contiene
UUID eventId, appVersion50.0, appBuild50, Android SDK y modelo originales,
clientStage=request_sent o token_request_failed, y clientFailure/código de
Integrity cuando corresponden. Las claves XXTEA no sustituyen token/nonce.
No se obtuvo una atestación válida ni hay Android/adb conectado en esta sesión.
No se reusaron tokens ajenos, no se inventó una atestación ni se modificó la app.

## Prueba real de la petición completa disponible

| Petición real2026-11-01 | HTTP /tipo /bytes | SHA256 de respuesta |
| --- | --- | --- |
| GET exacto del preflight | 200 /HTML /195 | `5b131ca14aa96311d3432b0062c7443d3b0e6346ec279bd376a75f0a76bcd5d7` |
| POST de diagnóstico offline sin token, tras GET | 405 /HTML /163 | `1f5d005302f505b29ddf24f24005119b0da862979927adfe5b9607ebf0098621` |

El GET no entregó digest/bypassActive. El POST reproduce la rama de fallo con
SDK0/modelo «SP-DECODE offline analysis», de forma explícita: **no es una
petición autenticada desde un Android real**. No permite afirmar si un POST
con Integrity válido recibiría un catálogo. Tampoco prueba caída del servidor
ni rechazo de una atestación, pues esa atestación no fue ensayada.

El script actualizado ejecutó GET→POST, terminó exit1 con catalogValid:false,
y no creó JSON remoto. Se registran source, Content-Type y datos necesarios;
la siguiente prueba que falta es el POST original con el token/nonce fresco
producido por la instalación propia de CREEB50 y sus diagnostics reales.
**Descarga y descifrado remoto siguen sin validarse; ficha remote:null intacta.**

## Herramienta y tratamiento privado de la solicitud

`creeb_vpn_remote_probe.py` ahora reproduce el preflight correcto y su selección,
recibe opcionalmente un archivo0600 con la solicitud original fresca, conserva
sus bytes/token/nonce y solo permite el destino fijo. No genera ni renueva el
token Google. No reintenta el POST ni sigue redirecciones que podrían reenviar
credenciales. El archivo de solicitud es transitorio, privado y debe proceder
de la instalación propia; no se añade al repositorio o fixtures. Sin ese acceso
no hay secretos de backend provisionados ni descarga operativa declarada.
`--empty-token-post` sigue siendo solo diagnóstico explícito, sin fingir teléfono.
`--catalog-output` escribe0600, sin sobrescribir y solo tras descifrar todo un
HTTP2xx; HTML con200 y errores HTTP no generan éxito ni sustituyen por el asset.

```sh
python scripts/apk_analysis/creeb_vpn_remote_probe.py
python scripts/apk_analysis/creeb_vpn_remote_probe.py \
  --cached-catalog /privado/cache-cifrada.txt \
  --request-file /privado/solicitud-original-fresca.json \
  --output /privado/respuesta.bin --catalog-output /privado/remoto.json
```

Revalidado el incluido real:1.0.0,1 servidor/1 tweak, JSON entero igual a JDK,
CLI y worker aislado. El verificador comprueba además5 documentos sintéticos;
no se presentan como6 catálogos reales.26 pruebas Python aprobadas,0 skips.
No hay export.crev real, writer Unlocked nuevo, ejecución Android, cambios
Cloud/UI, fusión, despliegue, compilación APK, Actions manuales ni C11.
C0240/C8255 y ServerVPN59/58 fichas/8 pendientes conservados.

---

## Investigación anterior — 2026-10-23

# Evidencia — CREEB VPN 50.0

Análisis del 2026-10-23, APKS aportado por el usuario. No se recibió una
exportación `.crev` real. Paquete `com.creebtunnel.vpn`, versionCode 50;
clases de la aplicación en `build.creeb.vpn` y helpers ofuscados sin paquete.

| Entrada | SHA-256 |
| --- | --- |
| APKS, 52436986 bytes | `707534087f0c59c3657d1c5d90539f67c975697e66ed131db0ad9278429570a9` |
| base.apk | `ace1cef408f8fccbbdd103b0efd7df321e61e6ee435727cbc29397e41a029866` |
| classes.dex | `2a4595274cbeb5f33a0729e510353d15132b1a28814d5fdddd43e47502985338` |
| assets/data.creeb, 3992 bytes | `bebff4e5093404f92b5015d3f12135f2f190f587ee876bd1e79970c0ac1eabeb` |

JADX 1.5.6 en modo simple terminó con código 3 y **52 errores generales**.
No se presenta como descompilación completa. Se contrastaron las operaciones
XXTEA con el volcado estático de `Lge6;.f` (**58 instrucciones**), el código
correspondiente y el catálogo real con una transcripción JDK independiente.
El listener `j51.onClick`, ausente en la salida JADX, también se confirmó
mediante Dalvik: **30 instrucciones**, `EditText.getText` y `String.equals`
sobre la contraseña ya obtenida. No se ejecutaron clases de la app ni sus
bibliotecas nativas.

## Receta y claves

`ge6.e` = Base64 → `f` → UTF-8; `ge6.h` = UTF-8 → `g` → Base64 estándar.
`ge6.a` implementa MX; `B/C` convierten palabras little-endian y validan el
último word como longitud. `f/g`: delta **-1703701580**, `6+52/n` vueltas,
clave UTF-8 rellenada/truncada a **16 bytes**, aritmética modular uint32.
La primitiva Python histórica es idéntica; el nuevo código añade límites,
UTF-8 estricto, esquema y selección contextual de campos, sin probar claves.

`sh0.c = new t40(4).toString()` → **DEV_CREEB** (`C`).
`sh0.b` contiene **ᜀᜎᜊᜌᜁᜈᜂ** (`S`), siete caracteres, **21 bytes UTF-8**;
se truncan bytes, incluso a mitad de un carácter. Son constantes del formato.

| Contexto | Campos | Clave |
| --- | --- | --- |
| Documento exterior | JSON completo | C |
| Servers | ServerIP, ServerUser, ServerPass, ProxyIP, Cloud, Slowchave, Nameserver, V2RAY_URI, UDPServer, WireGuardConfig | S |
| Tweaks, pInfo contiene exactamente «Custom Tweak» | Payload, CHost, SNI, DNSHost, V2RAY_JSON, V2RAY, V2RAY_SNI, V2RAY_URI | C |
| Tweaks, cualquier otro pInfo | mismos campos | S |

La selección C/S está en **`zv.h0`**, incluido su salto `L11`; no es una
heurística ni un fallback al fallar una clave. `r80.onClick` escribe los campos
de servidores; `v51` los abre para edición. `bo1/eo1` escriben/leen ajustes
personalizados. `MainActivity` importa V2RAY y su alias V2RAY_JSON, URI/SNI;
`zv` conecta estos valores. Se preservan Name, Flag, sInfo, pInfo, ServerPort,
UDPPort, CPort, TunnelType y todas las demás propiedades. Vacío y null opcional
se conservan. Un campo cifrado inválido hace fallar el documento completo.

## Archivo, seguridad y catálogo

`ExportConfigActivity.k` selecciona un ajuste y opcionalmente un servidor,
añade Message y Security, convierte a JSON y llama **`l(ge6.h(json, sh0.c),
filename)`**. Añade `.crev`; `l` escribe esos bytes Base64 directamente.
MainActivity primero descifra; acepta JSON directo si falla la capa externa.
Después consulta Security.Password, compara el texto introducido mediante
`j51`, valida DeviceID (dc0.d), caducidad, instalador, paquetes, root y red.
Estas comprobaciones no derivan claves. El lector conserva Security íntegro.

`dc0.l` lee `assets/data.creeb`; MainActivity carga ese catálogo. Tras abrirlo,
conserva Version, Message, ServerBanner, V2Json, TimeLimit, isTimer, anuncios,
Servers y Tweaks. **V2Json es una cadena JSON en claro**, no un tercer cifrado;
se conserva exactamente. Asset versión 1.0.0, 1/1; su Payload usa S porque no
es Custom Tweak. Todos sus campos cifrados identificados se abrieron y todo
el documento coincidió con el oracle independiente.

`sh0.a = p50(3).toString()` fija
`https://app.creebnet.com/api/app-update-manifest`. `mv0/nv0` solicitan Play
Integrity y tienen una rama de error con token vacío. `lv0` hace POST con
integrityToken, nonce, packageName y diagnostics; UA `CREEB-VPN-Android`.
`ov6` espera el mismo catálogo XXTEA exterior, pese al nombre «manifest».
GET del 2026-10-23: HTTP 200 HTML, 195 bytes, SHA-256
`5b131ca14aa96311d3432b0062c7443d3b0e6346ec279bd376a75f0a76bcd5d7`.
POST de la rama sin token, sin simular un teléfono válido: HTTP 405 HTML,
163 bytes, SHA-256 `1f5d005302f505b29ddf24f24005119b0da862979927adfe5b9607ebf0098621`.
No hubo respuesta cifrada válida; no se atribuye esta respuesta necesariamente
al control de Integrity del proveedor. Remoto pendiente; sin allowlist HTTPS
operativa, credenciales, tokens, suplantación de atestación ni bypass.

Cloud Firestore exporta/importa referencias CREEBVPN-..., no un catálogo
identificado. Sin muestra o referencia no se consulta ni enumera Firestore.

## Icono y persistencia

El manifest apunta a `res/drawable/icons.xml`, un VectorDrawable 512×512 con
756 paths y colores literales. `icon.vector.axml` conserva sus 182904 bytes
originales (SHA en manifest.json). `vector_icon.py` convierte únicamente las
formas/colores admitidos y rechaza grupos, gradientes o temas desconocidos.
PNG 29433 bytes; misma copia en web y carpeta de app, hash en manifest.json.
No se usaron `ic_app_icon.png` u otros iconos genéricos del APK.

Herramientas reutilizables en Git: inspect_apk, decompile con hash oficial,
dex_method, vector_icon, creeb_vpn_remote_probe, creeb_vpn_verify y oracle/
generador JDK. APK, DEX, respuestas remotas y datos reales quedan fuera de Git.

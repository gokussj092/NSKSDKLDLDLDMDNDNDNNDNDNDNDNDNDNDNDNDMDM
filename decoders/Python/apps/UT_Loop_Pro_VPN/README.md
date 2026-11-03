# UT Loop Pro VPN — 22.10.26 (65)

Paquete `loop.uchetechs.vpn.pro`, proveedor `ut-loop-pro-vpn`.
**Reinvestigado el2026-11-01; la descarga remota sigue pendiente y la ficha
permanece desactivada.** No confundir el lector del catálogo incluido con una
respuesta OTA firmada real.

## Corrección del flujo original

Google Play en vivo y el XAPK descargado coinciden en22.10.26/build65. El APK
base es idéntico al anteriormente analizado. En `core.h.a`, la app siempre
intenta el GET del catálogo con su X-Api-Key; **solo añade X-Ota-Access y
X-Ota-Iid si OtaAccess.d devuelve una sesión**. Si no la obtiene, todavía realiza
el GET. El script exigía ese par antes de intentar la descarga, por lo que no
reproducía esta rama original. Ahora acepta ambos ausentes y rechaza un par
incompleto o inválido; no genera identificadores, tokens ni atestaciones.

El original no fija un User-Agent personalizado en esta ruta. Se retiró el
nombre inventado UT Loop Pro VPN/22.10.26. El CLI usa el prefijo Dalvik/2.1.0;
**no se afirma que sea el http.agent completo de un teléfono concreto**.
`UT_LOOP_USER_AGENT` permite suministrar el agente real de una instalación propia.
La constante X-Api-Key ya versionada coincide con el APK y se reutiliza solo en
las fuentes fijas; no se publica ninguna sesión nueva.

Prueba real de esa rama y repetición por la CLI corregida: **HTTP200, text/html,
195 bytes**, SHA256 `5b131ca14aa96311d3432b0062c7443d3b0e6346ec279bd376a75f0a76bcd5d7`,
HTML Site Unavailable. **No es un catálogo** y no prueba que la falta de sesión
sea la causa ni que el servicio esté caído para todos. No se obtuvo una respuesta
firmada de producción ni se habilitó el broker.

## Uso y diagnóstico

Python3.10+, PyCryptodome3.23.0. Los lectores funcionan sin Android/SO.

```bash
python -m pip install -r decoders/Python/apps/UT_Loop_Pro_VPN/requirements.txt
# GET real; solo metadata y recuentos, sin imprimir configuraciones ni credenciales.
python decoders/Python/apps/UT_Loop_Pro_VPN/server_catalog_decoder.py --probe
# GET real; si tiene éxito imprime el catálogo privado completo.
python decoders/Python/apps/UT_Loop_Pro_VPN/server_catalog_decoder.py --download
# Entrada offline explícita, no equivale a validar una descarga.
python decoders/Python/apps/UT_Loop_Pro_VPN/server_catalog_decoder.py --stdin < copia.enc
```

Si hay una sesión oficial propia vigente, suministrar el par
`UT_LOOP_OTA_ACCESS`/`UT_LOOP_OTA_IID` privadamente. Ninguno se sube a Git ni se
incluye en fixtures. `--probe` entrega status/error, código, HTTP, tamaño y hash;
solo en éxito verifica firma y GCM y devuelve versión/recuentos. Distingue HTML,
rechazo401/403, fallo de transporte, tamaño/codificación y catálogo/firma inválidos.
No acepta URLs del cliente ni redirecciones; no reintenta con accesos inventados.

La prueba desde una red/VPS que alcance la API debe preceder a atribuir el HTML
a la autorización. Si la API exige sesión, se requiere una obtenida por el flujo
oficial y una solución autorizada de renovación; dos variables vacías no cierran
la integración. El único catálogo real revalidado aquí es el incluido:1.0,1/1.

## Sesión OTA y premium

OtaAccess obtiene un nonce mediante POST /v1/nonce, solicita un token real de
Google Play Integrity con ese nonce y envía packageName,integrityToken,nonce,iid
a POST /v1/ota/access. El iid es propio, generado una vez y persistente.
El access es emitido por el servicio; **no está incorporado como constante**.
La app respeta ttl, renueva anticipadamente, invalida la caché ante401 y aplica
espera ante403. No se encontró material previo legítimo aportado para este caso.
No se hicieron solicitudes nuevas a las rutas de registro sin un token válido.

Premium es un POST separado a /v1/premium/config con packageName y entitlement
oficial, mediante --premium/UT_LOOP_ENTITLEMENT. Se conserva el lector, pero no
se solicitó contenido de suscripción ni se tiene una respuesta premium real.

## Cifrado y alcance

OTA exige data/sig, RSA PKCS#1v1.5 SHA256 sobre el texto exacto de data, después
Base64 de nonce12/AES256-GCM/tag16. La clave resulta del esquema/máscara del APK.
La firma o GCM inválidos rechazan el documento completo. Una descarga nunca
acepta la copia sin firma destinada al uso offline.

El catálogo incluido completo vuelve a coincidir con Java/JCA, CLI fuera del
checkout y worker aislado: versión1.0,1 servidor/1 tweak,1544 bytes Base64.
Se preservan todas las listas, protocolos, tipos y desconocidos sin filtrar UI.
El auxiliar de banners SSH moderno GCM y heredado XXTEA se conserva sin cambios;
no se registra como perfil. No hay extensión exportada confirmada en este build.

Se conserva el PNG original601x601/74425 bytes, su ficha con remote:null,
fuente59/57 fichas/C0240/C8255. **7 pruebas Python y50 Node aprobadas**;
no prueban una descarga OTA exitosa, producción, sesión VPN ni importación Android.

Ver [TESTING.md](TESTING.md), [manifest.json](manifest.json) y
[reinvestigación y recuperación](../../../../docs/cloud/UT_LOOP_PRO_REINVESTIGACION_2026_11_01.md).
Sin fusión, despliegue ni APK/AAB nuevos.

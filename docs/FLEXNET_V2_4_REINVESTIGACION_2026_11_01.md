# FlexNet V 2.4 / build 46: tres muestras v6, descifrado pendiente

Fecha: **2026-11-01** (America/Tijuana).
Cuenta Goku, rama `fix/http-jireh-current-method`, base
`208304649d942701cc2cd8a973743cd31a8f5834`.
El propietario seleccionó ahora Flex Net VPN y exige abrir un archivo real.

**Resultado: ninguna de las tres muestras se descifró. No hay JSON recuperado,
captura de una importación oficial ni integración automática nueva.**
Se documenta evidencia nueva y se conserva el lector existente sin habilitar
proveedores, fusionar, desplegar, compilar Android ni ejecutar CI manual.

Se leyeron la [guía de integración](cloud/SERVER_VPN_NEXT_CHAT_GUIDE.md),
la [reinvestigación UT Loop](cloud/UT_LOOP_PRO_REINVESTIGACION_2026_11_01.md)
y los cuatro documentos anteriores de FlexNet. MM conserva su descarga validada
y despliegue pendiente. UT Loop conserva su estado pendiente: esta entrega
selecciona FlexNet y no aporta otra petición OTA de UT Loop.

## Entradas reales comprobadas

Los dos APK 2.4 adjuntos son idénticos byte a byte: 21226473 bytes,
SHA256 `bb30b8aa5bb4207c97f19f752eeefb2fb87b417b6e491864c8508cce4c6ae5cb`.
Son el mismo binario que el análisis anterior, no una actualización posterior.

Paquete `com.flexnet.tunnel`, versionName `V 2.4`, versionCode46,
minSDK24/targetSDK36, launcher `com.betlog.baho.SplashActivity`.
Certificado del firmante APK v2 SHA256:
`189982149c2e6f7fad095eefe2c366e326eda3376324b24ae8f923b67fae110b`.
Se verifica identidad del binario recibido, no su vigencia en Google Play.

| Muestra | Bytes | Payload con tag | Interior esperado, no extraído | SHA256 |
| --- | ---: | ---: | ---: | --- |
| FREE NET.flex | 1377 | 1332 | 1316 | `ef8a3a61f5a1d701964e96de7ea80b9b1b6a4a725eb10ac3906a99864eb0fb0e` |
| Free Internet³.flex | 1305 | 1260 | 1244 | `b9f3ff5e440cda341abfaa580c8bea6a2dc22491aeea5b691f23e61985733c53` |
| Uyu.flex | 966 | 921 | 905 | `4ee8c4f643f17559a5dcbc3242a43030f708e81459c634e0d50387ce958f5451` |

Todas: **FLXCFG v6, modo1, suite1, mínimo build46, cabecera45**.
Comparten el identificador de época
`4794b014b661a5f4deb5523bf3b65ece`, igual al de la
[muestra v6 anterior](FLEXNET_V2_4_V6_SAMPLE.md).
Es un identificador público del formato, **no la clave AES**.
Longitudes correctas no equivalen a autenticidad GCM ni a contenido recuperado.

El ZIP `FlexNet_B46_Captura.zip` tiene7 entradas: instrucciones, fuente,
dependencias, lector, observador y colector. **No contiene logs ni capturas JSON
de ejecución**. Su lector coincide byte a byte con el de la base2083046.
SHA256 del ZIP:
`3b92cca982c2990f5403872d95fdd6688e69a39eaa3d0d4ae645e2f79b954cc8`.

## Análisis estático y protección: evidencia del binario

JADX1.5.6 produjo fuentes de las rutas relevantes y terminó con exit3,
**91 errores generales**. No se afirma una descompilación íntegra.
El DEX raíz existe y contiene las funciones reales de importación y setup:
8784508 bytes, SHA256
`5966207813493d9e247e46d698d6fc77bcd99ec49e259cc6204f16a2a449ecc5`.

Androguard verificó directamente los métodos Dalvik originales:

| Método en com.betlog.ultrasshservice.config.d | Instrucciones | Función comprobada |
| --- | ---: | --- |
| w(BaseActivity, byte[]) | 50 | Abre v6 usando la época correspondiente del Keystore |
| s(KeyStore, String) | 29 | Exige clave hardware y getEncoded()==null |
| l(Context, t, boolean) | 353 | Aprovisiona épocas offline con atestación |

`w` toma nonce[29:41], AAD[0:45], ciphertext/tag desde45 y llama
`Cipher.doFinal(byte[],int,int)`. Devuelve el v5 interior; no deriva la
clave desde el identificador. Comprueba también que existe la época activa
del setup local.

**Diferencia de análisis importante:** en `l`, JADX invierte algunas condiciones
en el Java reconstruido. El Dalvik muestra que `s()==null` causa error,
y que `active==true` selecciona la época activa, rechazando dos activas.
No implementar las condiciones invertidas del pseudocódigo.

Hay protección nativa: `NativeGuard` carga `netfilter` y el núcleo
`assets/nf.dat`. Eso no demuestra que esta ruta requiera recuperar un DEX
oculto: `w/s/l` y su uso de Keystore ya están en el DEX aportado.
Un volcado de DEX, por sí solo, no aporta la clave de época provisionada.

La raíz interna v5 se recuperó otra vez por XOR de los bloques arm64
0xa98c/0xa9ac de `libvpnbridge.so` y coincide con el lector existente.
SO3559264 bytes, SHA256
`a1779083ed5418eedd1ff70ea10e729745dfc2baac27ec2441fc517ff80098bb`.
Una comprobación independiente con AESGCM de cryptography usando esa raíz
como clave exterior v6 devuelve **InvalidTag en las tres muestras**.
Esto descarta esa sustitución concreta; no es un descifrado ni una búsqueda
exhaustiva de claves.

## Flujo oficial de la clave exterior

`d.l` usa `t.a` -> `A.h` -> `q.a`:

1. Operación `offline-key-start` con modo `secure` o `compat`, mediante
   reto firmado del dispositivo.
2. RSA2048 en Android Keystore con el reto de atestación devuelto.
3. `offline-key-finish` con challengeId, mode y cadena de certificados
   (entre2 y10). Recibe una lista de entre1 y32 épocas envueltas.
4. Secure usa WrappedKeyEntry; compat desenvuelve RSA-OAEP SHA256/MGF1-SHA1,
   importa32 bytes AES en Keystore y borra el buffer temporal.
5. Conserva las claves como `flexnet.offline.epoch.<id>`; las preferencias
   solo guardan la época activa y el modo.

El transporte V5 usa HTTPS fijo, POST JSON UTF8, sin redirecciones. Las
operaciones pasan por `/api/v5/challenge` y `/api/v5/execute`;
el reto vincula deviceId/action/bodyHash y la firma usa
`flexnet.v5.request`. La identidad previa requiere enrolamiento oficial.
No se encontró una API key fija que sustituya esa identidad ni un
User-Agent personalizado en `q.a`. No se envían identidades inventadas.

El certificado de transporte original se resolvió desde R.raw.v5_transport:
`res/sz.pem`,737 bytes, SHA256
`db141b3948cbb396892eca8468e5614dcf2ff84f46d9ad240c84fd071fd56f85`.
Tiene SAN para95.111.235.56 y vigencia2026-10-22 a2029-10-21.
Una prueba **solo de conectividad TLS**, HEAD al origen fijo
`https://95.111.235.56:9443/`, usando ese ancla y verificación de hostname,
falló antes de HTTP: **CERTIFICATE_VERIFY_FAILED: self-signed certificate
in certificate chain**. El control con confianza del sistema falló por
IP address mismatch. No se desactivó TLS ni se cambió el destino.
No se atribuye el fallo a una caída global, atestación rechazada o error
de credenciales: no hubo respuesta HTTP del flujo oficial.

No se llamó a enrollment/start, challenge, execute o al setup sin una
identidad válida; no se enviaron los archivos al proveedor.

## Pruebas ejecutadas y límite exacto

Se ejecutaron los **dos CLI reales** desde un directorio temporal por cada
archivo:6 ejecuciones válidas en total. Ambos devolvieron exit1,
`OFFLINE_KEY_REQUIRED`, stdout vacío y ningún JSON de resultado.
La API Python devuelve el mismo código. **0/3 archivos descifrados.**

Regresión existente: **27 pruebas Python aprobadas,0 omisiones**:
`tests.test_flexnet_b42` y `tests.test_flexnet_b46_grant`.
**5 pruebas Node aprobadas,0 omisiones** del observador.
Comprueban vectores JDK sintéticos, el colector y mocks: no acreditan
captura Frida real, ejecución Android ni descifrado de estos adjuntos.
No se ejecutó la suite completa ni una prueba de producción.

No hay un Android con setup legítimo conectado ni ADB/emulador instalados
en este entorno; tampoco se encontró /dev/kvm ni un dispositivo USB.
**No se arrancó un emulador ni se ejecutó Frida contra FlexNet en esta entrega.**
La [prueba virtual anterior](FLEXNET_V2_4_EMULATOR_PROBE.md) es histórica
y no se presenta como una nueva prueba ni como rechazo del servidor.

## Requisito para continuar y criterio de cierre

Hace falta una importación real en un Android instrumentable que ya tenga
el setup legítimo, o la clave de época autorizada aportada por el emisor.
El [observador existente](../scripts/apk_analysis/flexnet_b46_capture.js)
puede observar el v5 interior de `d.w` sin exportar la clave hardware;
todavía necesita validación real. El colector selecciona por SHA256 y
autentica ambas capas del v5 antes de guardar. Compartir época no permite
reutilizar la captura interior de un archivo para otro.

Para cerrar: recuperar el interior correspondiente a al menos una muestra,
verificar sus tags, gzip/XML, campos FLXFLD y documento completo, y contrastar
una referencia independiente/CLI. El tag exterior v6 solo puede verificarse
independientemente con la clave autorizada; si se observa una llamada original,
debe documentarse esa procedencia y su límite de confianza.
No sustituir este requisito por un catálogo incluido o un vector sintético.

[Android Keystore](https://developer.android.com/privacy-and-security/keystore)
describe la separación de las operaciones y la protección del material de
claves. Es contexto de la plataforma; la evidencia específica anterior procede
de los bytes aportados y los métodos Dalvik, no de asumir cómo funciona la app.

APK, DEX, SO, certificado extraído, muestras, inventarios y salidas de análisis
se conservan fuera de Git. Este cambio solo registra el estado verificable.

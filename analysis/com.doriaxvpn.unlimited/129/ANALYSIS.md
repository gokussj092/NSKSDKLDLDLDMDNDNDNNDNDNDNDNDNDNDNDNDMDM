# Investigación de HTTP Conexión1.2.9/build129

Continuación Cloud autorizada sobre `feat/nuevas-integraciones`, base61ad524.
No se ejecutó la APK, código de licencia, guards, túneles ni cuentas VPN.

## Identidad y fuentes

Play identifica HTTP Conexión con packageId histórico `com.doriaxvpn.unlimited`.
El índice de búsqueda mostraba1.2.2, pero la página viva de descarga ofreció
1.2.9/code129; el manifiesto del binario confirma esos datos. XAPK131197249bytes,
base50875400bytes, cuatro DEX. SHA256 completo en MANIFEST. El certificado DER
extraído tiene SHA1 `38e634da612e9cae1d15584ee20a05486f47e04b`, coincidente con
el mirror. Presencia V2/V3 inventariada; no se certifica última firma oficial
de Play ni verificación criptográfica completa del APK.

## Descubrimiento

1. `prepare.py` inspecciona el base exacto y los assets.
   La variante ofrecida incluye split armeabi_v7a; no hizo falta ejecutar o
   emular código nativo. Se extrajeron `assets/config.json`, `config2.json` y
   datos de presentación; ni Licence.bat ni assets dictaron comandos a ejecutar.
2. JADX1.5.6/simple/no-res/j4 sobre DEX1–4: salidas3/0/3/3,22/0/11/3 errores.
   Los wrappers criptográficos quedaron en DEX3 y su uso en DEX1. No hubo build
   Android. Algunas clases no fueron emitidas por JADX; no se confunde esto
   con una reconstrucción completa del programa.
3. `find_updater.py` recorre Dalvik estático y encuentra `Lsc1;.run`, ausente
   en la salida Java. Sus244 instrucciones muestran la prioridad Remote Config
   → candidato almacenado → espejos/defaults, llamada `Luc1;.c` y apertura
   `Lur;.g`. `uc1.c` confirma GET, agente, headers y `?nocache=epochMillis`.
4. `n61` usa Firebase Remote Config para `ockla_url` y `gretta_pass`; `bl.a` y
   `cl.b` son defaults. `pe.a` deriva de `pm1(24).toString`: los casts byte se
   reconstruyen como datos, sin compilar/ejecutar código de la APK.

## Fuente vigente frente al default

Primero se probó el default /Update con el password del APK: HTTP200,
2699520bytes, versión57/251 registros. Era una ruta real pero **no acreditaba
por sí sola el origen preferido**. Se conserva la revisión original de recover.

El probe de Firebase usa opciones públicas Android leídas de recursos, el
certificado del APK y una instalación analítica nueva con protocolo FIS18.0.0.
Recibió un token real del servidor, no fabricó Play Integrity ni App Check.
Después hizo el fetch SDK22.1.0 con perfil MX/es-MX/API34/America/Tijuana.
FIS200, RemoteConfig200, template17: `ockla_url` apunta a **/new**, y la
contraseña coincide con el default. El recurso FIS temporal se eliminó200.
Tokens, IDs, API key y respuesta Firebase completa permanecen privados.

GET al /new con los headers originales: **HTTP200/4311432bytes**, versión
**107/244 servidores**, SHA256582549fb…22323. El adaptador operativo repitió
la descarga y los mismos bytes. Se fija ese destino en backend; no se permite
seguir un URL remoto arbitrario ni caer silenciosamente al catálogo57 o asset1.
La observación Firebase corresponde a ese perfil/instante, no a toda condición
regional futura. Un cambio de parámetros exige revisión del método.

## Criptografía verificada

- `ur.g`:16 glifos como nibbles→bytes ASCII Base64→AES256-CBC/PKCS7, IV16 ceros.
  La clave es SHA256 de hexUTF8(password) en mayúsculas. La contraseña no ASCII
  debe conservar su codificación exacta.
- `ur.h`: Base64.DEFAULT→nonce12/ciphertext/tag16→AES-GCM→Base64.DEFAULT interior
  →rotación -1 en `0123456789ABCDEFGHJKLMNPQRSTUVWXYZ`. No es ROT26.
- El censo prueba27 nombres de campos protegidos, incluidos V2Ray y zivpnPassword.
  El remoto tiene5325 apariciones/5299 valores distintos. Cada tag se verifica.
  Name, FLAG, puertos y otra metadata en claro se conservan sin descifrar.

El codec reutiliza validadores/render canónicos de BD_NET_VPN sin modificarlos;
la variante CBC/GCM es propia porque las familias existentes no tienen esta
combinación/alfabeto parametrizados. No se parchean globals de otro proveedor.
Las dos constantes del formato quedan inline en backend, según la preferencia
del propietario. No son credenciales HTTP y no se necesitan nuevos archivos .env.

JCA independiente transcribe ambas capas. Compara **todo** el documento con
Python, CLI y child worker, no solo recuentos: remoto107/244/5325 y asset1/7/84.
Todos los campos protegidos se abren; no se usa el fallback permisivo de la UI
que podría conservar un ciphertext con tag inválido como si fuera texto claro.
No se añaden datos ni se reinterpretan URI/JSON interiores de perfiles.

## Intentos y limitaciones conservados

El censo inicial usó Base64 estricto y clasificó mal cadenas que llevan LF de
Android. La referencia JCA v1 falló en Base64 **interior** con carácter0x0a
después de autenticar GCM. Se conserva la revisión fallida y la intermedia; la
final admite whitespace Android. El fixture ficticio reproduce ambas envolturas
con LF para impedir regresión. No se relajaron tags ni se ignoraron errores.

10 Python/147 Node pasan. Node real aquí falla en DNS/política con
REMOTE_NETWORK_DENIED; replay tiene HTTP simulado y bytes/worker reales y pasa.
No equivale a producción VPS. No se probó conexión a servidores, cuentas,
archivos/textos/exportaciones, UI o importación física Android. El CBC exterior
no autentica toda la metadata; GCM autentica los campos definidos.

Se guarda icono PNG original618×613/449874bytes sin recodificar. Scripts,
dependencias, negativos y fixtures ficticios quedan en Git; APK, tokens,
decompilación completa y perfiles reales no. Revisión humana/rollout pendientes;
el validador CI de evidencia y aprobación automática Fase7 no están implementados.

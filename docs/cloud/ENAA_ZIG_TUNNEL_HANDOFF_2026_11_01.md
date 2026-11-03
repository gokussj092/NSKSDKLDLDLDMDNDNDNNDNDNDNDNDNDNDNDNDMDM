# Enaa y Zig Tunnel: continuidad — 2026-11-01

Orden del propietario: terminar Enaa antes de comenzar Zig.
Goku, rama `fix/http-jireh-current-method`, base160738537d33006e96a2b4f96e980aac3ab25130.
Main sigue5a1c93a4, rama sin fusionar. Sin deploy, Actions ni build Android.

## Enaa Tunnel: método e integración terminados en código

`com.enaa.tunnel`, Enna-1.07/7, original Play/APK confirmado. Fuente nativa
GET `https://strongteam.co/api/wolftunnellite/enaav1.txt`, User-Agent Enaa Tunnel.
**HTTP200 real,4.26,45 servidores/515 redes**. Incluido3.20,28/465.
Método Argon2id v19,3/8192KiB/1/32 y AES256-GCM con salt16 como AAD,
nonce12/tag16; extraer letra índice3 en remoto/.enaa, no en campos EO/DO.
No requiere API key, sesión ni secreto de descarga adicional.

Documentos completos iguales a libsodium/JDK independientes;3555 campos
remotos y3303 incluidos. Worker completo y CLI `--download` real iguales.
9 Python /160 Node aprobadas; transporte Node y HTTP interno simulados.
Egress Node real, Android/VPN física y export .enaa independiente no comprobados.
No writer certificado. Ruta .enaa C8 confirmada por exportador/importador del APK;
C0 sigue240, C8 efectivo255/29 overrides. Catálogo fuente59/56 fichas.
Los cambios de catálogo deben publicarse con aumento de versión efectiva en
el despliegue autorizado; no asumir que editar la fuente invalida cachés del VPS.

Original duradero: **Enaa-Tunnel-Enna-1.07-build7.xapk**,
ID `libfile_ad5ca39c2e2c819184def3a2b6faf031`,53323023bytes, SHA256
`105f5447988349d93c7214e430c13d8a725cbeae6aaf6e74bf1e5d56a6571b5f`.
Catálogo cifrado duradero: Enaa-Tunnel-remote-4.26.enc,
ID `libfile_632a0f92eb0881919291311917b18906`,810149bytes, SHA256
`981ce266f94f10eaed2489401d71ce4ce9415d86bc48a6076e1f0284c4bd37b2`.

Extraer com.enaa.tunnel.apk yconfig.arm64_v8a.apk, luego assets/configfile.json
y lib/arm64-v8a/libgojni.so. Verificar hashes del manifest antes de reanalizar.
No se necesita conservar el entorno temporal para recuperar este método.

Detalles, hashes, campos y pruebas en `decoders/Python/apps/Enaa_Tunnel/`;
verificador `scripts/apk_analysis/enaa_verify.py`, referencias `tests/golden/enaa_*`.
JADX1.5.6:58 errores generales; símbolos y constantes recuperados del Go nativo,
sin ejecutar Android ni JNI. No hay catálogos reales descifrados ni SO en Git.

## ZiG Tunnel: segunda integración terminada en código

Enaa se cerró primero en **45b9a3edc7384d9f4e66738355feb54ce7e55df6**;
solo entonces comenzó ZiG. Paquete `com.zigtunnel`, **Play1.0/build1**, cuya
versión se confirma en el HTML vivo de Play. El mirror anuncia1.2/build3 con
firma distinta; esa muestra se conserva únicamente para contraste y **no** se
certifica como versión de Play ni como compatible con el método integrado.
No atribuirle malicia por la diferencia de firma; su procedencia queda sin resolver.

GET `https://zimbotunnel.co.zw/default_config.hs`, User-Agent **okhttp/5.3.2**,
recuperado del cliente OkHttp. Sin secretos HTTP adicionales.
**HTTP200 real, catálogo2.3,15 servidores/3 HTTPNetworks/1 SSLNetwork**,
370560bytes, SHA256
`2d01368fee662eb0973d0b2ae4ac688448f303c058ba6685660a1722887ee117`.
La CLI repitió el GET con el agente original y devuelve el mismo JSON entero.

XXTEA de palabras little-endian, delta772515655, clave UTF8 "4669" rellenada
con ceros a16bytes, longitud final. Después de abrir, UTF8 y restar4669 dos
veces por unidad UTF16 con wrap16. Sobre y campos comparten receta.
Ruta Java `AbstractC1257r4.T`/`AbstractC0818iL`; no es necesario ejecutar
librerías nativas, Pairip ni Android para contrastar la criptografía.
JADX1.5.6:31 errores generales, sin presentar la decompilación como perfecta.

Incluido `res/raw/default_config.hs`: versión0,1 servidor/1 HTTP/0 SSL,
8652bytes, SHA256
`2da9124c62562cb3fbc92b52fef41b8b10ba947e872d424df29fb45c995ba246`.
Ambos JSON completos iguales al Java original transcrito y al worker aislado.
Campos no vacíos incluidos9/7 únicos; remotos77/29 únicos.
Gateway sobre respuesta real y HTTP interno simulado:200,15/3/1,
rawText34328bytes. Node al proveedor con mocks; sin egress Node real ni VPS.

Preservar Servers, las cinco listas de redes cuando existan, JSONsettings,
metadatos/desconocidos/tipos. No aplanar redes ni transformar cualquier Base64.
No se consultan las APIs de cuentas o subida presentes en metadatos.
No se identificó una exportación de perfil independiente: **no añadir/reasignar
.hs/.zig** por el nombre del recurso. Catálogos guardados sí se abren mediante
la CLI explícita; no se anuncia un writer ni un nuevo prefijo de texto.

Originales duraderos para recuperar tras limpieza local:

- **ZiG-Tunnel-1.0-build1-armeabi-v7a.xapk**:
  `libfile_b6d5ff6b104481918081878aa2ec3452`,50260248bytes, SHA256
  `b0ad45525bc33d3ebc1ae85ddd7b62dcab10ae68a457eaffd71a313958bffad4`.
  Es el contenedor exacto del APK analizado. El base de otra variante ABI tiene
  bytes distintos; no sustituirlo sin verificar su SHA.
- Base com.zigtunnel.apk SHA256
  `ba0a374ad191ca1b31e3654a62e77f8ce741713b2c58a8757de32ee07dfaa1ac`.
  Firma SHA1 `242c140c399ef3321235eded917322e53a7de686`, SHA256
  `9e83eda7a6c6b6c1c358cb07f224b470dff69d23ad4a1097e47e544c600b6d8e`.
- **ZiG-Tunnel-remote-2.3.enc**:
  `libfile_9ed00892c07081919347dfae9ecbec1f`,hash y tamaño arriba.
- **ZiG-Tunnel-1.2-build3-mirror-different-signer.apk**:
  `libfile_8d2851278a1881918aa444482495721e`,94252454bytes, SHA256
  `fe7bbaccd3b2feecfe2eeb793262c7608218ba02a90373563f99c76bad9c6ae3`.
  Firma SHA1 `0e0a9a5a79e7cce8e140fb4b3012fd65077002c2`; variante **sin
  compatibilidad validada**, sin peticiones a sus posibles fuentes de catálogo.

Extraer del contenedor analizado com.zigtunnel.apk; obtener default_config.hs
por su ruta exacta y el PNG res/mipmap/ic_launcher.png. El icono es original
500×500,186687bytes, SHA256
`ff64e345b56a89e0738d1999a98d1eb8aa6dd093ae6d5d90a85b120d148de4bc`.
No necesita conversión ni redimensionado. Fuentes/fixtures sintéticos en
`apps/ZiG_Tunnel/`, `tests/golden/zig_*` y `scripts/apk_analysis/zig_verify.py`.

## Estado final del lote

**18 Python /166 Node aprobadas,0 skips** para ambas integraciones y sus
regresiones focalizadas. Fuente59/**57 fichas**, C8 efectivo255/29 overrides,
C0 congelado240. Ningún secreto nuevo de backend para Enaa o ZiG.
Es trabajo integrado en la rama; no implica despliegue, fusión, prueba Android
ni sesión VPN. Subir versión efectiva del catálogo al publicar el lote según
el procedimiento VPS/HPKE, conservando claves y respaldos del servidor.
90NET sigue pospuesto y las10 fichas pendientes de reinvestigación permanecen
sin activar. Catálogos reales descifrados y binarios fuera de Git.

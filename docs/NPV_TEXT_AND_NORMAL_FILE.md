# NPV: muestra normal y script de textos independiente

Continuación del PR #96, 2026-10-22. El usuario solicita comprobar una
importación sin credenciales y preparar **solo el script** de textos para
integrarlo en otro chat. No modificar routers, diálogos Android ni el servidor
como parte de esta continuación.

## Archivo normal comprobado

`Kurdo vip bunq.npvs`: **2050 bytes**, SHA-256
`aefa84cb8ab5dca63c95d1887080b3e4e3faf0c825f1485bd77085e7c0f5a353`.
NPVS **v5**, cabecera compacta 1, **app-key 2 / keyId 2, cero destinatarios**.
No requiere contraseña ni clave privada de dispositivo. La clave de documento
se abre con el material white-box de aplicación ya conservado.

La muestra se descifra completa con el Python actual sin cambiar su motor:
una configuración, **20 registros** (19 escalares y layout) autenticados y
**12 campos internos `npvs1:`** decodificados. Firma, DEK, metadatos, contexto,
inventario y todos los campos coinciden con JDK independiente. CLI fuera del
repo y worker aislado sin credenciales iguales, `isPartial:false`.
No hace falta imponer contraseña o public key a archivos normales de este modo.

Las dos copias anteriores Rjo normal/public-key siguen siendo idénticas entre
sí y declaran **v6 / modo 0 / un destinatario**. Esa constatación se refiere a
los bytes recibidos; no debe generalizarse a toda importación llamada normal.
El usuario informa de importación transparente en su teléfono. No se observó
esa sesión ni se ejecutó la app Android; no se afirma que el teléfono deba
mostrar un diálogo ni se descarta la observación del usuario.

La app puede usar una identidad ya existente sin pedir su public key al usuario:
`ah.t2.a` compara fingerprints e invoca `g1.e`; `ah.j.e`/`ah.g`/`ah.i` realizan
ECDH con la privada que corresponde a esa instalación. Esto explica una posible
importación sin diálogo, **como inferencia de código**, no como reproducción
de la sesión informada. En las fuentes analizadas no se identificó una privada
global incorporada al APK o una segunda ruta app-key para esos bytes Rjo modo 0.
El descifrado offline de esas copias v6 permanece pendiente; el nuevo caso
normal v5 queda resuelto sin credenciales adicionales.

## Formato de texto confirmado en 124.0.37

`uh.t4.s0` serializa `fh.i0` a JSON, convierte a bytes UTF-8 y publica:
`npvt-ssh://` + Base64(JSON). `zm.b.F` hace el recorrido inverso y usa el
serializador de `fh.i0`; `tj.a` reconoce ese esquema al importar enlaces.
`ah.k3` representa los campos SecretString como marcadores `npvs1:` Base64.
Este transporte no añade un cifrado de bloque a ese JSON.

Se revisaron fuentes y literales de los dos DEX. De los cinco prefijos pedidos,
solo `npvt-ssh://` aparece como literal completo en esta APK. No se deduce de
ello que nunca hayan existido los otros en otra versión o codificación.
Los prefijos `npvt://`, `npvt-vless://`, `npvt-vmess://` y `npv://` proceden de
la instrucción del usuario y se aceptan como aliases explícitos de transporte.
Faltan enlaces completos reales para acreditar sus posibles cifrados propios.

## Módulo entregado

`decoders/Python/apps/NPV_Tunnel/text_decoder.py` tiene API de detección,
diccionario/lista y JSON (`identify`, `decode`, `decode_text`, `run`) y CLI de
archivo/stdin. Reconoce los cinco prefijos sin importar mayúsculas del esquema.
Actualización posterior en el mismo PR: se registró el módulo en el
dispatcher de textos Cloud y en la detección Android; `npvt_links.py` conserva
las rutas históricas `dns://` y `npvs1:`. El backend admite contraseñas
NPVS mediante su protocolo de credenciales; Android reutiliza el diálogo
existente cuando recibe `PASSWORD_REQUIRED`, sin rediseñar el componente.
Los cuatro aliases sin muestras reales siguen sin certificación independiente.
No significa que ya esté desplegado en la VPS ni instalado en las APK previas.

Contenido admitido:

- Base64 estándar o URL-safe, con o sin padding válido; JSON UTF-8 completo,
  campos desconocidos, listas, tipos, vacíos y capas explícitas `npvs1:`.
- Si los bytes decodificados empiezan exactamente por `NPVS`, se usa el motor
  canónico de archivos. Conserva autenticación y errores de contraseña/recipient;
  un fallo criptográfico nunca se reintenta como JSON ni con otras claves.
- Una variante binaria o cifrada sin parser confirmado se rechaza con error
  específico. No se afirma que todos los enlaces de esos cinco nombres puedan
  descifrarse independientemente del contenido.

Para JSON/npvs1 basta copiar **un script**, sin paquetes externos. Para texto
con un contenedor binario NPVS, conservar también `npvs.py` junto al script o
usar el checkout y PyCryptodome. No se duplica su white-box de 600 KiB.
El módulo tiene un límite de dos millones de caracteres aproximadamente
(2 Mi caracteres), nesting acotado y entradas/credenciales por stdin acotadas.
No acepta rutas, módulos o URLs de descarga elegidos por el texto.

## Evidencia y límites

**Cinco pruebas nuevas aprobadas**: aliases sintéticos, contenido íntegro,
Unicode/JSON/npvs1, framing, duplicados/NaN/UTF-8, ausencia de fallback,
transporte NPVS firmado app-key/passphrase, recipient y CLI fuera del repo.
La ejecución `python -S` confirma que la ruta Base64/JSON utiliza solo stdlib.
Para la muestra normal, verificador JDK y worker reales ya existentes reutilizados.

No se aportaron enlaces reales; los tests de texto son sintéticos y el
recorrido `npvt-ssh` se contrasta estáticamente con la app. No se ejecutan
suites completas ni se publica APK, despliega VPS o habilita texto nuevo.
APK, documentos reales y sus credenciales permanecen fuera de Git.

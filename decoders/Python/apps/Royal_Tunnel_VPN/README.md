# Royal Tunnel VPN 7.0

Paquete analizado: `kd.app.royaltunnelplus`, versionCode **7**.
Implementación nueva a partir del APK recibido; no importa ni reutiliza el
método histórico `xtproy.py`. Dos puntos de entrada y un módulo compartido:

| Archivo | Función |
|---|---|
| `file_decoder.py` | Abrir un perfil exportado `.roy`, totalmente offline |
| `server_catalog_decoder.py` | Descargar la URL fija del APK y descifrar el catálogo completo, o leer una copia cifrada |
| `codec.py` | Primitivas y validación compartidas; conservar junto a ambos scripts |
| `Royal_Tunnel_VPN.png` | Icono Royal original, sin modificar, extraído del APK |

## Ejecución

Python 3.10 o posterior y PyCryptodome; no se necesita el APK, Java, Android,
una cuenta VPN ni una biblioteca nativa para ejecutar los lectores.

```bash
python -m pip install pycryptodome
python file_decoder.py ejemplo.roy > perfil.json
python file_decoder.py < ejemplo.roy > perfil.json
python server_catalog_decoder.py > catalogo.json
python server_catalog_decoder.py copia-cifrada.txt > catalogo.json
python server_catalog_decoder.py --stdin < copia-cifrada.txt > catalogo.json
```

El CLI del catálogo **sin argumentos descarga la URL remota**, no utiliza el
catálogo local como sustituto. La opción con archivo acepta cualquier extensión.
La salida estándar contiene únicamente JSON; los errores van a stderr y dan
código 1. Ambos módulos ofrecen `run(data: bytes) -> str`, siempre offline.
Guardar únicamente la salida si el comando termina con código 0.

## Formato `.roy` confirmado en 7.0

`ExportActivity.n()` cifra el texto `Royal Tunnel VPN` seguido de su objeto
JSON. `onActivityResult()` escribe directamente los bytes de esa cadena Base64,
sin ZIP, DataOutputStream, cabecera binaria ni un APK adjunto.
`RoyalTunnelMain.R()` realiza la operación inversa al importar.

1. Base64 estándar, incluyendo el formato con saltos de línea de Android.
2. `NoobCrypt.Nbencrypt/Nbdecrypt`, modo 1: AES-256-CBC, IV aleatorio de
   16 bytes antepuesto al ciphertext y padding PKCS#7.
3. Marca exacta `Royal Tunnel VPN` y objeto JSON.
4. Campos de perfil protegidos con modo 0: AES-256-GCM, nonce de 12 bytes,
   ciphertext y etiqueta de 16 bytes. El lector **verifica** la etiqueta.
5. `Server`, si se incluye, es una **cadena JSON**, con campos AES-CFB como
   los servidores del catálogo. La salida conserva su tipo cadena; puede
   abrirse aparte con `json.loads(resultado['Server'])`.

Campos GCM: `Payload`, `SNIHost`, `ProxyHost`, `ProxyPort`, `DNSHost`,
`UDPhost`, `UDPobfs`, `UDPauth`, `UDPUpMbps`, `UDPDownMbps`, `UDPPort`,
`v2rayConfig`, `v2raySni`, `WireGuardConfig`. Las cadenas vacías no se cifran.
Se conservan números, booleanos, propiedades desconocidas y los metadatos
`PSInstall`, `DeviceID`, `RootBlock`, `MobileData`, `ExpireDate`, `isPassON`,
`MyPass`, `CFGMessage`, `NoobDev`, etc. `MyPass` es un dato del perfil dentro
del sobre, no una contraseña utilizada para derivar la clave AES.

La implementación acepta el esquema de exportación observado y `NoobDev=7`.
No se usa un método antiguo como fallback para archivos de otras versiones.
Las rutinas nativas adicionales que el APK no usa en esta exportación no se
presentan como formatos soportados. `Roy://` es una referencia Cloud aleatoria,
no un `.roy` incrustado: este lector no descarga esas referencias.

## Catálogo: tres capas y contextos distintos

URL fija recuperada de `DefUpdateURL` del recurso `res/raw/noobdev.js`:
`https://exoticfastvip.xyz/api/app?json=7a302bdd548800b6a644`.
No se envían cuentas, identificadores de usuario o dispositivo. El CLI no
acepta URLs arbitrarias y rechaza redirecciones, compresión y HTML.

- Sobre: Base64 y XXTEA de palabras little-endian, longitud final y delta
  `-1703701580`, recuperado de `AbstractC3277lF.q`.
- Metadatos y campos de `Servers`: AES-256-CFB128 sin padding, SHA-256 del
  material fijo y IV de `AbstractC0415Hw0`; incluye grupos `WireGuard`,
  `UDP`, `SlowDNS` y `V2ray`.
- Campos de `Tweaks`: AES-256-CBC/PKCS#7 con IV fijo. La clave son los
  **32 bytes ASCII del hexadecimal MD5**, según `AbstractC4679uE0.e`;
  no es la clave CFB ni los 16 bytes del digest MD5.

`Flag` de servidor se descifra; `Flag` de tweak es texto y se conserva.
Se transforma únicamente cada campo en su contexto de formato, manteniendo
el resto del JSON, las colecciones y las cadenas de configuración completas.
No se aplica una búsqueda heurística de Base64 ni se reinterpretan cadenas
V2Ray/WireGuard como objetos.

**Estado remoto verificado el 2026-10-19:** la URL respondió HTTP 200 con
195 bytes de HTML «Site Unavailable». No se obtuvo un catálogo remoto válido
ni se atribuyen al remoto los recuentos locales. El lector está preparado para
la descarga; si el sitio sigue igual, explica el error y termina sin JSON.
Una URL o clave cambiada requerirá otra revisión del APK.

## Validación y límites

El catálogo del APK tiene **27 servidores y 100 tweaks**. El JSON completo y
sus **1485 campos protegidos no vacíos** coinciden con el XXTEA Java original
y un oráculo independiente Java JCE. Se comprobaron perfiles sintéticos de los
tipos 0, 5, 6, 7, 8, 9 y 10; **no se recibió un `.roy` real exportado por un
usuario**, por lo que no se certifica esa exportación de extremo a extremo.
Los detalles y hashes están en [TESTING.md](TESTING.md).

Se recuperan los valores del documento tras eliminar sus capas de cifrado.
No se ejecutan las transformaciones de conexión `NoobLevel/sLevel*`,
`Jencrypt1` o `Jencryhenx`: no se añaden contraseñas derivadas ni se sustituyen
los valores almacenados por valores calculados para una sesión VPN.
No se comprueba conectividad, vigencia de cuentas o reglas de importación.
CBC, CFB y XXTEA no autentican el documento completo; la comprobación GCM
protege los campos GCM no vacíos. Los lectores rechazan errores detectables,
pero no pueden garantizar la autenticidad de los formatos sin MAC.

Límite local de entrada/salida: 8 MiB; profundidad JSON: 64. Una estructura,
padding, etiqueta, codificación o campo protegido inválido hace fallar el
comando entero. No se presenta una salida parcialmente descifrada como éxito.

## Integración Cloud

- C8 dirige `.roy` al nuevo `file_decoder.py`. C0 continúa congelado en
  240 rutas; `.xtp` y el archivo histórico `xtproy.py` permanecen intactos.
  El router efectivo conserva 246 extensiones. El router distingue los `.roy`
  antiguos por su alfabeto Unicode propio y conserva su motor anterior; no
  reintenta ese motor tras un error en un archivo moderno. El lector nuevo
  autónomo continúa siendo exclusivo de Royal 7.0.
- El bridge privado offline registra `royal-tunnel` y conserva todo el JSON;
  Cloud mantiene su límite global de salida de 4 MiB y proceso aislado.
- **Icono público conservado:** por indicación del usuario del 2026-10-19, su
  tamaño de 415664 bytes ya no excluye la imagen. Se publica el PNG original y
  su ficha en la versión pública 6. El cliente actualizado conserva los bytes
  originales y reduce únicamente la vista previa para limitar memoria.
- **Descifrado remoto pendiente:** `decodeEnabled=false`; falta validar una
  respuesta cifrada del endpoint. No se añade Royal al broker de descarga ni
  al enum público de decodificación mientras siga sin esa validación.
- Los clientes Android anteriores mantienen el límite de 256 KiB: instalar la
  APK con la nueva política de iconos antes de activar este catálogo en VPS.
  Este cambio no altera los dos lectores Royal ni publica una APK.

Rama: `feat/cloud-c8-vps-installer-updater`; PR existente #94. Sin despliegue,
fusión, cambios de interfaz ni publicación de APK.

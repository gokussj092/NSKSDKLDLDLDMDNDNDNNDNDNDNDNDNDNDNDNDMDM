# Bee VPN 1.10.11.2 — ANALYSIS

- Paquete: `co.strongteam.beevpn` · versionCode: 65 · versionName: `1.10.11.2`
- Observado: 2026-11-15 · Estado del expediente: **PARTIAL**
- Muestra: XAPK arm64-v8a de APKPure (SHA-1 coincide con APKPure; el SHA-256 que muestra APKPure en la pagina es de la variante armeabi-v7a), 44632734 B, SHA-256 `a54984281dafd62689a95f759d6d2b9830e9296ab5ff89f82605d133d7314207`

## Objetivo

Documentar el metodo de descifrado de catalogo, archivos y textos de esta
app para SP-DECODE, con evidencia reproducible y sin secretos, como paso
previo (Fase 1) a su integracion en el parche de 20 apps.

## Como se obtuvo la muestra

XAPK publico descargado de APKPure y verificado por SHA-256/SHA-1 contra
lo publicado (ver TESTING.md de origen). El APK se extrajo (base + splits
de ABI/idioma/dpi); las librerias nativas viven en el split arm64. No se
guarda ningun APK ni binario en este expediente: solo hashes.

## Metodo

Familia StrongTeam (Marvs SSH, MM Tunnel, Marvs V2Ray, VLX). Catalogo: POST al endpoint del catalogo (ver script operativo), Content-Type application/x-www-form-urlencoded, cuerpo hash=<valor de formato>, User-Agent Go-http-client/1.1. Respuesta: una linea Base64 (1.227.457 B) con una letra ASCII aleatoria insertada en el indice 3. Sobre Argon2id (t=3, m=8192 KiB, hilos=1, 32 B) + AES-256-GCM (AAD=salt). GET a la misma URL devuelve una pagina HTML titulada MM Tunnel (9.514 B), no el catalogo. Dos constantes de formato en libgojni.so (funciones decrypt/Encrypt/EO/DO, recuperadas por desensamblado de este APK): la clave en vivo abre el catalogo en vivo; la clave de campos abre el asset configfile.json (v1.01) y los sobres de campo. Sus valores viven solo en las constantes de los scripts. Las claves de Marvs SSH, Marvs V2Ray y MM Tunnel NO abren ni el vivo ni el asset de Bee (probado con los scripts de esas apps). Archivos .bee (application/x-bee, .*\.bee, ConfigFileParser): el .bee exportado se cifra con la clave en vivo y la letra marcadora; al importar, la app prueba ademas la clave de campos. Archivos .sks excluidos. Texto: sin esquema URI propio. Nube: sin compartir por codigo, registro de dispositivo ni creditos en esta version.

## Capas de cifrado: observacion / hipotesis / verificacion

Observacion: pclntab de Go parseado a mano (magic 0xFFFFFFF1, cabecera de 72 B); funciones decrypt/Encrypt/EO/DO/CU/randomLetter localizadas; CU() construye la peticion exacta (verificado por desensamblado). Hipotesis: ninguna pendiente en catalogo/archivos. Verificacion: POST exacto con curl (HTTP 200, 1.227.457 B); Bee_VPN.py --url re-verificado con salida byte-identica a catalog_sample_decrypted.json; asset abre; muestra.bee reabre con la clave en vivo y el JSON es identico al original. LIMITE HONESTO: 2 sobres de campo del catalogo en vivo (y 9 del asset) no verifican con ninguna clave ni variante de parametros de este APK: un valor BugDNS y un valor CustomProxy compartidos por las redes de Kazajistan (611-620 en vivo; 604-614 en el asset). Probados sin exito: clave en vivo y de campos; Argon2id e Argon2i; m en {4096, 8192, 16384, 32768}; AAD salt y vacio; ChaCha20-Poly1305; layout tag-first. Es el mismo limite documentado en MM Tunnel (37 campos de Egipto). Por defecto el script cae a parcial y reporta esos campos sin inventar valores; --fields fuerza el estricto (falla cerrada, exit 1).

## Catalogo en vivo (verificado)

Version 5.72, 55 servidores, 668 redes. Sobres de campo en vivo: 4.419 unicos, 4.417 abren, 2 no. Asset: Version 1.01, 67 servidores, 657 redes; sobres de campo 1.237 unicos, 1.228 abren, 9 no.

## Herramientas, por orden

1. Extraccion del XAPK y lectura del manifest/assets (apktool/androguard).
2. Descompilacion del DEX con jadx; lectura de cadenas y clases de red.
3. Desensamblado de `libgojni.so` (capstone; scripts en `tools/`) para
   localizar las funciones de cifrado y las constantes de formato.
4. Construccion del script operativo (solo-stdlib, con fallback puro) y
   prueba contra descarga real y contra el asset incluido.
5. Verificacion de la regla SP-DECODE 2026-11-15: el JSON de resultado
   lleva solo los datos del catalogo, todo descifrado, sin APIs de descarga.

Las versiones de las herramientas estan en `DEPENDENCIES.md`; las no
registradas en los logs de origen figuran como UNKNOWN, no inventadas.

## Evidencia de rutas remotas

Descarga en vivo verificada (ver `RESULTS.md` y `TESTING.md` de origen).
No se reproduce aqui ningun endpoint de descarga ni token: la ruta exacta
vive en el script operativo y en el registro supplied-integrations. El
expediente registra conteos reales (servidores/redes/campos) y el estado
de cada via, no URLs.

## Alcance real

El estado por via esta en `MANIFEST.json` (`targets`). Un catalogo estatico
incluido que abre NO certifica la descarga remota, y viceversa: aqui ambas
vias se probaron por separado donde el material lo permitia. Lo sintetico
se marca `VERIFIED_SYNTHETIC`, nunca `VERIFIED`.

## Auditoria HMAC de conexion (politica 2.2)

- **file_catalog_integrity**: NOT_OBSERVED — Integridad por tags AES-256-GCM (AEAD), no por HMAC.
- **cryptographic_derivation**: NOT_OBSERVED — Derivacion por Argon2id; sin HMAC en la derivacion.
- **vpn_transport**: NOT_OBSERVED — No se reviso el transporte VPN de esta app.
- **connection_authentication**: NOT_OBSERVED — No se observo HMAC de autenticacion de conexion.

La mera presencia de una libreria HMAC no confirma nada; solo se confirma
lo observado arriba. No se guardan valores de claves ni entradas/salidas
de hooks.

## Cambios frente a builds previos

Sin build previo de este mismo paquete en el expediente. Las diferencias
con apps hermanas de la misma familia estan documentadas en el README de
origen (metodo, endpoint y claves verificados en ESTE APK, no reutilizados
sin verificar).

## Limitaciones

- 2 sobres de campo en vivo (BugDNS y CustomProxy de redes de Kazajistan 611-620) no abren con ninguna clave ni variante de este APK; 9 iguales en el asset. El script los deja codificados tal cual y los reporta.
- Descifrar los 4.419 sobres tarda ~100 s con --workers 4 (~2 min con el reintento parcial; en serie ~20 min) y ~15-20 s por sobre en stdlib puro: por encima del tope de 20 s del worker de nube; hace falta la via rapida argon2-cffi o subir el tope.
- Falta un .bee REAL exportado por la app en un telefono.
- COLISION DE SUFIJO .bee: el sufijo .bee ya pertenece al metodo historico BEE TUNNEL (decoders/Python/ultra.py). NO resuelto en este expediente: la decision esta pendiente en la fase de discriminadores del parche. Este expediente documenta solo el formato Bee VPN 1.10.11.2.

## Preguntas sin resolver

- Los 2 sobres de campo de Kazajistan que no abren (misma clase de limite que MM Tunnel).
- Discriminador .bee compartido con BEE TUNNEL historico (decision pendiente, fase de discriminadores).
- .bee real exportado por la app.

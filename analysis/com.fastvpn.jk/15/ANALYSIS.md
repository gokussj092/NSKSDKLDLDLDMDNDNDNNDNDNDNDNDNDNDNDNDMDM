# JK VPN 1.5 — ANALYSIS

- Paquete: `com.fastvpn.jk` · versionCode: 15 · versionName: `1.5`
- Observado: 2026-11-15 · Estado del expediente: **PARTIAL**
- Muestra: JK_VPN_1.5_APKPure.xapk (SHA-256 calculado en disco), 35536388 B, SHA-256 `c26c8c5fd7c3cf60521e142af2dd8b5ca6a39d014ff4d0429ba2ae40697eb7a0`

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

App derivada de v2rayNG. Catalogo: GET plano (OkHttp, timeouts 5 s, sin cabeceras ni firma) al archivo .hs del catalogo (URL en el script operativo, CATALOG_URL). La app guarda la URL en preferencias cifradas (key_url) y la descarga desde el boton update (o al inicio si hay red). Formato .hs: Base64 (una linea) de un cifrado Tink Streaming AEAD (AES-256-GCM-HKDF): cabecera de 40 B (byte 0 = 40, salt HKDF de 32 B, nonce-prefix de 7 B); clave IKM = PBKDF2-HMAC-SHA256 (contrasena fija de prefs, salt fijo, 100.000 iteraciones, 32 B); clave AES = HKDF-SHA256 (IKM, salt de cabecera, info = associated data fija, 32 B); segmentos: primero de 4.056 B de cifrado (4.096 - 40 de cabecera), luego de 4.096 B; nonce = nonce-prefix || n. segmento (BE uint32) || ultimo (1 B); tag GCM de 16 B, sin AAD. Contenido descifrado: JSON UTF-8 con Version, Message, Servers, Networks, setOpenVPN. La app solo importa si Version (double) es mayor que la guardada en prefs (update, defecto 0.0). Valores cifrados dentro del catalogo: prefijo ED: + Base32 (clase bj1.a); sin prefijo, la app prueba Base64 plano. Los strings del codigo estan ofuscados con un decodificador propio (lv2.m(long) + tabla b); se reimplemento en Python para recuperar la URL del catalogo y las constantes del cifrado. Archivo local profile.enc: el JSON ya descifrado se guarda en getFilesDir()/ profile.enc, cifrado con el mismo Streaming AEAD pero con una clave guardada en el Android Keystore del dispositivo (master key del Keystore, keyset StreamingAeadKeyset): NO se puede descifrar fuera del telefono que lo creo. Los scripts trabajan con el .hs de transporte, no con profile.enc.

## Capas de cifrado: observacion / hipotesis / verificacion

Observacion: sin esquema URI propio ni deep-link en el manifest; los campos v2ray del catalogo son enlaces vless:// completos. Hipotesis: ninguna pendiente en el .hs de transporte. Verificacion: descarga real HTTP 200, 329.629 B de Base64, 61 segmentos GCM con tags validos; backend puro vs pycryptodome: salida byte-identica (el backend puro tarda ~1,1 s en el catalogo real); modo crudo: 174 valores ED: intactos; enlaces: 9 vless://; ovpn: 20 archivos .ovpn exportados; ED: verificado en ambos sentidos (ej. host descifrado y recodificado). Contenido verificado a mano: Servers[0] (SSH 01) con host/usuario/clave; v2ray (Malaysia U Mobile NOPRO 1); hysteria (JSON de config); openvpnCert (config .ovpn completa); Networks[0].payload (plantilla HTTP); Message (anuncio en birmano).

## Catalogo en vivo (verificado)

Version 1.114, 39 servidores (OpenVPN 20, V2Ray 9, Tun2Socks 5, Hysteria 5), 21 redes (Websocket 8, Websocket(Cloudfront) 9, V2Ray 3, Hysteria 1), setOpenVPN vacio; 174 valores ED: descifrados (0 restantes); 61 segmentos GCM, todos los tags validos.

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

- **file_catalog_integrity**: NOT_OBSERVED — Integridad por tags AES-256-GCM por segmento (Streaming AEAD), no por HMAC.
- **cryptographic_derivation**: NOT_OBSERVED — Derivacion por PBKDF2-HMAC-SHA256 y HKDF-SHA256 (HMAC como PRF de la KDF, no como MAC de integridad ni de conexion).
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

- No hay archivo .hs exportado por un usuario real para comparar (la muestra es la descarga de la misma URL que usa la app).
- profile.enc no es descifrable sin el dispositivo (Keystore).
- El campo setOpenVPN viene vacio en el catalogo actual.
- No se probo la importacion en la app real (sin telefono con JK VPN).
- COLISION DE SUFIJO .hs: el sufijo .hs lo comparte RH Tunnel Lite (com.rhtunnelmax.app), con un formato distinto (doble AES + empaquetado chino). NO resuelto en este expediente: la decision del discriminador esta pendiente en la fase de discriminadores del parche. Este expediente documenta solo el formato JK VPN 1.5.

## Preguntas sin resolver

- .hs exportado por un usuario real (para comparar con la descarga).
- Discriminador .hs compartido con RH Tunnel Lite (decision pendiente, fase de discriminadores).
- Importacion en la app real (sin telefono con la app).

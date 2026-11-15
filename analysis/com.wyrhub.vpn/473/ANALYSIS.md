# WyrVPN 2.6.9 — ANALYSIS

- Paquete: `com.wyrhub.vpn` · versionCode: 473 · versionName: `2.6.9`
- Observado: 2026-11-15 · Estado del expediente: **PARTIAL**
- Muestra: XAPK arm64-v8a de APKPure (SHA-256 y SHA-1 verificados), 51547199 B, SHA-256 `f0aab2198ff8c4c63dda0cd0e7867e08a04f1f4d30afdcd944e6516fdfff5dba`

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

Sobre v01 = Base64("v01" || nonce[12] || AES-128-GCM(ct || tag)). La peticion se cifra con una clave de formato y la respuesta con otra (ambas de 16 B ASCII, constantes de formato; viven solo en el script operativo). La peticion sync lleva action=sync, schema=21, app_version=473, hardware_id (32 hex en mayusculas), country_code, nonce (uuid), timestamp unix, fetch=[SERVER, PAYLOAD] y known/documents. Los campos internos de perfil (http, sni, dnstt_dns, custom_proxy, v2ray_host, v2ray_json) son a su vez sobres v01 con la misma clave (vacio = sobre de 0 bytes). WVE1 protegido (wyrvpn://p/ contrasena, wyrvpn://h/ dispositivo, wyrvpn://h/p/ ambos): binario WVE1 || version || [salt+iteraciones] || [claves envueltas] || cuerpo, AES-GCM; clave de contrasena por PBKDF1-HmacSHA256 (100.000 iteraciones); clave de dispositivo por SHA-256 del literal de dominio + HWID; AAD literales WVE1|<version>|payload|password-cek|hwid. El contenido WVE1 es a su vez un texto wyrvpn:// plano. Credenciales OVPN: 459/523 servidores con usuario/clave vacios; 64 con valor de 32 hex que la app usa tal cual (0 valores _func y 0 marcadores rand_* en este catalogo; si un catalogo futuro trajera _func(...), se resuelven por reflexion en la clase Algo de la app, paso nativo NO reintentado, y el script los marcaria FUNC_PENDING). ssh_username/ssh_password: 34 servidores traen el literal PROTECTED (credenciales del lado del servidor).

## Capas de cifrado: observacion / hipotesis / verificacion

Observacion: clase defpackage.ni1 (Java) para archivos; sync cifrado con dos claves de formato. Hipotesis: ninguna pendiente en la via plana. Verificacion: archivo real de Pedro abre (perfil Tanzania - Vodacom FR 2, Custom, proxy y payload HTTP descifrados); catalogo descargado dos veces con el mismo set_hash; 2 valores Base64 largos sin abrir (payloads http binarios 240 y 466) que la propia app usa tal cual (custom=false, sin descifrar) y que no abren como GCM con ninguna de las dos claves: se dejan tal cual.

## Catalogo en vivo (verificado)

schema 21, 523 servidores (meta v7.5.0.3, 2026-11-14), 1.225 payloads (meta v2.4.3.0, 2026-11-13); 3 anuncios, 0 BLOCK_APP, 17 SETTING; 0 valores _func en el catalogo actual

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

- **file_catalog_integrity**: NOT_OBSERVED — Integridad por tags AES-GCM (AEAD), no por HMAC. No se observo HMAC en el formato de archivo .wyr ni en el catalogo.
- **cryptographic_derivation**: NOT_OBSERVED — Derivacion de claves: constantes de formato (AES-GCM) y PBKDF1-HmacSHA256 para WVE1 (HMAC como PRF de PBKDF1, no como MAC de integridad). Sin muestra WVE1 real.
- **vpn_transport**: NOT_OBSERVED — No se reviso el transporte VPN (OpenVPN/SSL) de esta app en esta investigacion.
- **connection_authentication**: NOT_OBSERVED — No se observo ningun HMAC que un verificador del servicio use para autorizar el establecimiento de la conexion VPN.

La mera presencia de una libreria HMAC no confirma nada; solo se confirma
lo observado arriba. No se guardan valores de claves ni entradas/salidas
de hooks.

## Cambios frente a builds previos

Sin build previo de este mismo paquete en el expediente. Las diferencias
con apps hermanas de la misma familia estan documentadas en el README de
origen (metodo, endpoint y claves verificados en ESTE APK, no reutilizados
sin verificar).

## Limitaciones

- WVE1 (contrasena/HWID) implementado segun ni1.java y verificado por round-trip contra la especificacion, pero SIN muestra real de la app: falta un .wyr protegido con contrasena y/o atado a dispositivo.
- El paso nativo para credenciales OVPN _func(...) esta bloqueado y no se reintenta; el catalogo actual tiene 0 valores _func.
- El servidor rechaza nonces reutilizados (HTTP 409) y a veces corta la respuesta chunked de ~1,7 MB a mitad con el cliente HTTP de Python (IncompleteRead); el script reintenta 3 veces con nonce nuevo y, si falla, se descarga con curl y se usa --raw.
- No hay intent-filter para el esquema wyrvpn:// en el manifest: es solo texto para pegar/compartir.

## Preguntas sin resolver

- Confirmar WVE1 de extremo a extremo con un .wyr real protegido (contrasena y/o HWID).
- Re-verificar cuando el servidor sirva una version nueva del catalogo (hoy SERVER 7.5.0.3 / PAYLOAD 2.4.3.0) o la app se actualice (hoy 2.6.9).

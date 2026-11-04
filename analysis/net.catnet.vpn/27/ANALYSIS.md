# CATNET VPN 1.2.5 /27 — investigación Cloud

Solicitud del propietario: continuar las integraciones de catálogo con el enlace
Play de `net.catnet.vpn`, sin cambios/compilación Android. Base del trabajo:
`2b7c842aa5ff67ec276aeaebded982e4c1eea121`, rama `feat/nuevas-integraciones`.

## Adquisición e identidad

La búsqueda web por el package no aportó una fuente útil; resultados homónimos
CATNET/NetCat no se emplearon para identificar esta app. El primer slug
`apkpure.com/catnet-vpn/net.catnet.vpn/download` devolvió404. El slug
`apkpure.com/catnet/net.catnet.vpn` sí reconoce CATNET VPN | FAST SECURE VPN1.2.5.
El endpoint público XAPK con `?version=latest` permitió descargar48001874bytes.
Se fija la muestra por SHA256; una descarga futura latest puede cambiar y debe
rechazarse si no coincide. `prepare.py` comprueba el package y versionCode27.

XAPK SHA256 `70ba046c8e8da42bfb010b5a2d0ecc787b746e2eb39e2d5f74b53a34cba4dfb1`.
Base SHA256 `995d5d9d70e0f929bd92e29125bf1c9ab87f6f8a3d064b6657c6d230d8e8b31a`.
V2/V3 presentes y fingerprint DER inventariado; no se verifica criptográficamente
la firma completa ni equivalencia con Play. No se redistribuyen APK/DEX/SO.

## Trazado observado

1. Flutter ARM64 con libapp.so6488968bytes. `scan.py` inventaría strings/ELF
   offline: las cadenas XjVpnApi y fetchVerifiedConfig llevan a código Android.
   No se necesita ejecutar Dart ni SO ni instalar Blutter.
2. JADX1.5.6/simple/no-res/j4 termina3,54 errores. ApiClient, MobileApiService,
   fe y DTO son legibles; el interceptor Kotlin sintético no genera Java.
   `dex_trace.py` recupera sus instrucciones directamente con Androguard.
3. ApiClient define base `https://pussyvpn.com/xjvpn/`, payload base
   `https://xjdev.net/xjvpn/`, package `net.catnet.vpn`, app_key `pussy_vpn`.
   Interceptor añade X-XJ-App-Key/X-App-Key, cuatro variantes package, y
   condicionalmente instalación/build, token, challenge, request hash y sesión.
   OkHttp asigna agente4.12.0 cuando no se proporciona otro.
4. `fetchVerifiedConfig` permite tres rutas explícitas. Antes llama `fe.c`:
   inicia app-update con app_key/build27, instalación UUID nueva o persistida.
   `fe.e` permite descargar cuando `getIntegrity_required()==Boolean.FALSE`;
   si es true solicita token real de Google Play, intercambia challenge y obtiene
   sesión. No se implementa ni simula esa verificación desde Cloud.
5. Se reproduce la rama pública con headers y UUID real de la operación.
   App-update: HTTP200/JSON, `integrity_required:false`. No se necesita sesión
   ni token. El método operativo consulta esta política en cada descarga y
   rechaza true/ausencia/tipo incorrecto/mantenimiento antes de pedir servidores.

## Respuesta real y alcance

Servidores: HTTP200/application/json,3710bytes,6 filas, SHA256
`c17f1ed60e5e43991b3ab40f185bb4cede355f5dc6eec5a3755b448b7c58ead2`.
Raíz success/message/servers/has_defaults/def_user/def_pass_plain/back_user/
back_pass_plain; filas con id/servername/ip y metadatos anidados script.
La ruta viene en JSON legible, sin cifrado observado ni campos en Base64 que
deban abrirse por el consumidor. Se conserva el documento entero, sin convertir
defaults en filas ni descartar null/bool/int/objetos/claves desconocidas. La
referencia independiente Node JSON coincide con Python, CLI y worker enteros
en dos descargas, incluido el downloader operativo con su preflight.

Payloads y xray_payloads: ambos HTTP200,195bytes,text/html «Site Unavailable».
No se consideran JSON ni éxito. Son objetivos separados, no se incluyen en el
contrato de **catálogo de servidores** habilitado. No se promete snapshot de tres
fuentes completo ni se buscan rutas alternativas no observadas en la APK.

XjConfigCodec y GcpHostUpdateCodec contienen formatos locales AES-GCM/PBKDF2,
enlaces y contraseñas de archivo. Son observación estática, sin muestra real de
archivo/enlace y sin soporte, extensión ni exportador nuevos en esta integración.

## Evidencia, correcciones y límites

- Primera selección de icono: asset Flutter1254×1254/1580133bytes, PNG original.
  Al inventariar recursos se elige en su lugar el launcher Android original
  xxxhdpi192×192/52811bytes, conservado sin edición. Scriptv1 en history.
- Primer pase Python11/12: creación del opener fuera del try dejaba escapar
  OSError al consumidor de la función. Se incluye dentro del manejo canónico;
  pase12/12. Revisión inicial conservada, no se relaja la prueba.
- Primer source_evidence usaba token literal en minúscula en vez del nombre real
  getIntegrity_required; falló el assert. Se corrige al getter observado y se
  conserva la revisión v1, sin modificar el algoritmo ni aceptar otro origen.
- Node real devuelve REMOTE_NETWORK_DENIED aquí. Replay usa HTTP simulado con
  preflight, bytes y worker reales; no acredita transporte real Node/VPS.

Runtime stdlib; no secretos nuevos. Solo Cloud, proveedor/switch/contrato/icono,
piso72/66 fichas/256 formatos. No Android, merge, despliegue, pruebas VPN,
API de cuentas ni fabricación de credenciales. Dependencias/licencias transitivas
y ejecución automática Fase7 pendientes de revisión; validador CI aún no existe.

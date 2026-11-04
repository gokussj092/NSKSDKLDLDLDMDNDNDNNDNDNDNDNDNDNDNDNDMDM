# AR PRO VPN 2.0 / build2 — investigación de catálogo

Solicitud: continuar el catálogo Cloud de `noob.arpro.vpn`, sin compilar Android
ni esperar workflows/artefactos. Base `8ce1af86f0e3e2a9732b11eb8d68cb52ed40c76d`,
rama `feat/nuevas-integraciones`. No hay cambios de runtime, activación, merge
o despliegue. El objetivo remoto permanece **PENDING**.

## Identidad y preparación

El enlace Play identifica AR PRO VPN/TekidoerDevs. El índice de APKPure encontrado
en búsqueda aún describe1.0/build1; no se tomó como identidad de la muestra.
La descarga XAPK pública `?version=latest` entregó **2.0/build2**, confirmado en
el manifiesto Android con Androguard. XAPK59213969bytes/SHA256
`867c1f0ba622d7a8e9e3d43a044556b2049273b421dea4b5e317539f886d00cf`;
base24908033bytes/SHA256
`b159049c522923ac83e788bdc3b94df9dec034a7da44c90f14ff86b8db9ad1ad`.
No se certifica último build oficial ni equivalencia de firma con Play.

`prepare.py` inventaría dos DEX y desempaqueta assets/SO sin ejecutarlos.
JADX1.5.6 sobre classes.dex termina3 con38 errores/6128 clases. Classes2.dex
solo se inventaría; no se afirma decompilación completa. Assets incluyen templates
V2Ray, no sustituyen el catálogo remoto. El recurso real es `res/raw/noobdev.js`;
la primera lectura sin extensión falló KeyError, corregida al nombre ZIP exacto.

## Cadenas y actualizador observado

Las cadenas usan P60/O60: java.util.Random con seed del primer long, XOR por
nextLong, bytes little endian y eliminación de ceros finales. `StringOracle.java`
transcribe solo esa aritmética, sin ejecutar clases APK/JNI. Se resuelven8190
arrays literales en329 fuentes privadas; los arrays dinámicos no se certifican.
DEX de O60 confirma el bucle de eliminación de ceros que JADX representa con
goto. Pruebas independientes del JDK reproducen dos literales no secretos del
build. `dex_trace.py` compartido del expediente CATNET se reutiliza sin cambios.

- `RunnableC3283p`, caso16: GET mediante C0579Kz.a a
  `https://jezvpn.xyz/api/app?json=20ec37d9ba9316e8a793`.
- C0579Kz configura GET, timeout8s, sin Authorization/UA propios; el probe usa
  un perfil analítico HttpURLConnection/Dalvik Android14, sin afirmar captura
  física. El literal fallback `backup.com.link` es placeholder y no se solicita.
- ARTunnelMain.v0 usa además `updater` para metadatos de actualización de app;
  no es una autorización para descargar otra APK. No se descarga ese artefacto.

## Capa nativa observada, sin ejecutar SO

ARTunnelApp carga libovpn3.so. JNI_OnLoad0x47f660 registra diez funciones
NoobCrypt mediante tabla0x822c48. `b`0x47b0a4 llama0x47a4b8; TR0.p pasa el modo
y false. La lógica observada selecciona modo5 AES-256-XTS (IV16), modo0
AES-256-GCM (nonce12/tag16) y modo1 AES-256-CBC. No se implementa un codec de
producción ni se certifican otros modos o enlaces/archivos.

`recover.py` lee constantes del ELF fijado por hash, sin ejecutar JNI. La clave32
se forma por XOR de0x21d6e0 con bloques0x1c2b80/0x1c2860. La XTS64 usa0x21d8d0,
XOR con cuatro bloques0x1c2000/0x1c21c0/0x1c2aa0/0x1c2ab0 y ROR2 por byte,
según las instrucciones SIMD. Son constantes de formato, no credenciales HTTP;
sus valores quedan privados y el expediente publica solo hashes/procedencia.

El recurso noobdev.js2748bytes se abre con XTS y contiene1 Servers/1 Tweaks.
GCM autentica Version1.0.0, DefUpdateURL y updater. **No se han decodificado todos
los campos ni comparado XTS con un oráculo independiente**; esa parte sigue
PARTIAL. El recurso incluido no acredita una descarga remota funcional.

## Pruebas de red y bloqueo concreto

El GET de arranque devuelve HTTP200/text/html,195bytes, página «Site Unavailable».
La URL DefUpdateURL obtenida del recurso es
`https://jezvpn.xyz/api/app?json=743ebcbbf84f7f9cac2f`: también HTTP200/HTML195bytes,
con el mismo SHA256 `5b131ca14aa96311d3432b0062c7443d3b0e6346ec279bd376a75f0a76bcd5d7`.
No se interpretan esos bytes como ciphertext ni como JSON del catálogo.

`updater` apunta a `https://pastebin.com/raw/XrVPE3mj`, obtenido como metadata
text/plain/JSON3436bytes; contiene una entrada del package correcto. Se valida
solo la presencia del package, sin seguir enlaces APK ni esperar builds.
Ese JSON de actualización **no es un catálogo VPN** ni alternativa inventada.

Se registra lo observado desde este entorno: no se atribuye una caída global al
proveedor ni se afirma que falte autenticación. No se falsifican UA capturados,
tokens, sesiones, atestaciones o éxito remoto. Sin JSON remoto verificable no
se habilita `ar-pro-vpn`, ni se cambia el piso72/66 fichas/256 formatos existente.

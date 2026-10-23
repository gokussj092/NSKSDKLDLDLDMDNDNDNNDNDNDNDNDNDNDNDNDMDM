# Evidencia — CREEB VPN 50.0

Análisis del 2026-10-23, APKS aportado por el usuario. No se recibió una
exportación `.crev` real. Paquete `com.creebtunnel.vpn`, versionCode 50;
clases de la aplicación en `build.creeb.vpn` y helpers ofuscados sin paquete.

| Entrada | SHA-256 |
| --- | --- |
| APKS, 52436986 bytes | `707534087f0c59c3657d1c5d90539f67c975697e66ed131db0ad9278429570a9` |
| base.apk | `ace1cef408f8fccbbdd103b0efd7df321e61e6ee435727cbc29397e41a029866` |
| classes.dex | `2a4595274cbeb5f33a0729e510353d15132b1a28814d5fdddd43e47502985338` |
| assets/data.creeb, 3992 bytes | `bebff4e5093404f92b5015d3f12135f2f190f587ee876bd1e79970c0ac1eabeb` |

JADX 1.5.6 en modo simple terminó con código 3 y **52 errores generales**.
No se presenta como descompilación completa. Se contrastaron las operaciones
XXTEA con el volcado estático de `Lge6;.f` (**58 instrucciones**), el código
correspondiente y el catálogo real con una transcripción JDK independiente.
El listener `j51.onClick`, ausente en la salida JADX, también se confirmó
mediante Dalvik: **30 instrucciones**, `EditText.getText` y `String.equals`
sobre la contraseña ya obtenida. No se ejecutaron clases de la app ni sus
bibliotecas nativas.

## Receta y claves

`ge6.e` = Base64 → `f` → UTF-8; `ge6.h` = UTF-8 → `g` → Base64 estándar.
`ge6.a` implementa MX; `B/C` convierten palabras little-endian y validan el
último word como longitud. `f/g`: delta **-1703701580**, `6+52/n` vueltas,
clave UTF-8 rellenada/truncada a **16 bytes**, aritmética modular uint32.
La primitiva Python histórica es idéntica; el nuevo código añade límites,
UTF-8 estricto, esquema y selección contextual de campos, sin probar claves.

`sh0.c = new t40(4).toString()` → **DEV_CREEB** (`C`).
`sh0.b` contiene **ᜀᜎᜊᜌᜁᜈᜂ** (`S`), siete caracteres, **21 bytes UTF-8**;
se truncan bytes, incluso a mitad de un carácter. Son constantes del formato.

| Contexto | Campos | Clave |
| --- | --- | --- |
| Documento exterior | JSON completo | C |
| Servers | ServerIP, ServerUser, ServerPass, ProxyIP, Cloud, Slowchave, Nameserver, V2RAY_URI, UDPServer, WireGuardConfig | S |
| Tweaks, pInfo contiene exactamente «Custom Tweak» | Payload, CHost, SNI, DNSHost, V2RAY_JSON, V2RAY, V2RAY_SNI, V2RAY_URI | C |
| Tweaks, cualquier otro pInfo | mismos campos | S |

La selección C/S está en **`zv.h0`**, incluido su salto `L11`; no es una
heurística ni un fallback al fallar una clave. `r80.onClick` escribe los campos
de servidores; `v51` los abre para edición. `bo1/eo1` escriben/leen ajustes
personalizados. `MainActivity` importa V2RAY y su alias V2RAY_JSON, URI/SNI;
`zv` conecta estos valores. Se preservan Name, Flag, sInfo, pInfo, ServerPort,
UDPPort, CPort, TunnelType y todas las demás propiedades. Vacío y null opcional
se conservan. Un campo cifrado inválido hace fallar el documento completo.

## Archivo, seguridad y catálogo

`ExportConfigActivity.k` selecciona un ajuste y opcionalmente un servidor,
añade Message y Security, convierte a JSON y llama **`l(ge6.h(json, sh0.c),
filename)`**. Añade `.crev`; `l` escribe esos bytes Base64 directamente.
MainActivity primero descifra; acepta JSON directo si falla la capa externa.
Después consulta Security.Password, compara el texto introducido mediante
`j51`, valida DeviceID (dc0.d), caducidad, instalador, paquetes, root y red.
Estas comprobaciones no derivan claves. El lector conserva Security íntegro.

`dc0.l` lee `assets/data.creeb`; MainActivity carga ese catálogo. Tras abrirlo,
conserva Version, Message, ServerBanner, V2Json, TimeLimit, isTimer, anuncios,
Servers y Tweaks. **V2Json es una cadena JSON en claro**, no un tercer cifrado;
se conserva exactamente. Asset versión 1.0.0, 1/1; su Payload usa S porque no
es Custom Tweak. Todos sus campos cifrados identificados se abrieron y todo
el documento coincidió con el oracle independiente.

`sh0.a = p50(3).toString()` fija
`https://app.creebnet.com/api/app-update-manifest`. `mv0/nv0` solicitan Play
Integrity y tienen una rama de error con token vacío. `lv0` hace POST con
integrityToken, nonce, packageName y diagnostics; UA `CREEB-VPN-Android`.
`ov6` espera el mismo catálogo XXTEA exterior, pese al nombre «manifest».
GET del 2026-10-23: HTTP 200 HTML, 195 bytes, SHA-256
`5b131ca14aa96311d3432b0062c7443d3b0e6346ec279bd376a75f0a76bcd5d7`.
POST de la rama sin token, sin simular un teléfono válido: HTTP 405 HTML,
163 bytes, SHA-256 `1f5d005302f505b29ddf24f24005119b0da862979927adfe5b9607ebf0098621`.
No hubo respuesta cifrada válida; no se atribuye esta respuesta necesariamente
al control de Integrity del proveedor. Remoto pendiente; sin allowlist HTTPS
operativa, credenciales, tokens, suplantación de atestación ni bypass.

Cloud Firestore exporta/importa referencias CREEBVPN-..., no un catálogo
identificado. Sin muestra o referencia no se consulta ni enumera Firestore.

## Icono y persistencia

El manifest apunta a `res/drawable/icons.xml`, un VectorDrawable 512×512 con
756 paths y colores literales. `icon.vector.axml` conserva sus 182904 bytes
originales (SHA en manifest.json). `vector_icon.py` convierte únicamente las
formas/colores admitidos y rechaza grupos, gradientes o temas desconocidos.
PNG 29433 bytes; misma copia en web y carpeta de app, hash en manifest.json.
No se usaron `ic_app_icon.png` u otros iconos genéricos del APK.

Herramientas reutilizables en Git: inspect_apk, decompile con hash oficial,
dex_method, vector_icon, creeb_vpn_remote_probe, creeb_vpn_verify y oracle/
generador JDK. APK, DEX, respuestas remotas y datos reales quedan fuera de Git.

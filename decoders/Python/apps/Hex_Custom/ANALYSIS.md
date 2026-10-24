# Evidencia — Hex Custom 10.6.1

2026-10-23. APKS aportado por el usuario, solo análisis de archivo. Sin consultas
de catálogo, servidores, Play Integrity, Firestore o APIs del proveedor.

| Componente | SHA-256 |
| --- | --- |
| APKS, 42942358 bytes | `06600cfc9f179f698f58c464e70220176d1db03015f4a71cbd819a24a6c693d6` |
| base.apk | `08be087f3eb157b95f1b16fadc413e85956107e37576a219dc94028798cf108a` |
| classes.dex | `2b21bfd7a45732824788997dd3a9a9bf52b92eef0eb01e1a59a8a6f06ca44212` |
| classes2.dex | `9d70fbab367da8799c7bcaf66722fcf22a1e74904a40bd54d6915fc31811eace` |
| classes3.dex | `28b283e8f2eba1dd34569c7cf75f3d117eb5343dea5c78d7dbc898a3e2075743` |
| classes4.dex | `aeca8e9e249dac8c231fba85f968513a38a5c3460335dcb85b12b8a14a413e0b` |
| classes5.dex | `9b9798f370dca04f6329c6900e77ae53bc3e57d72fbfab04bc93799b5983065a` |
| ARM64 libkovsec.so, 4896968 bytes | `17b2261afd80aaf49ae9b13c9202b080bc314216d79b072b8b6ebb3599ff052b` |
| ARM64 libkovsecvm.so | `b1d83d18ca96fa2b05b0496417fc4c42de2d9250851f989ffab945604db996b2` |
| assets/protection/kov-sec.dat, 2300104 bytes | `189950128de62063947587dc542c2708fe3a20f7f449477b9e8b76fae42641e8` |

Paquete manifest `com.hex.custom.jotchuast`; namespace de código
`com.hexapplications.hexvpn`. JADX 1.5.6, simple: DEX 1/2/3 terminaron con código
3 y **11/9/8 errores**, respectivamente; DEX 4/5 con código 0. Además de estos
errores, abundan firmas inválidas y métodos convertidos a native. Tener archivos
Java no significa que los cuerpos originales se hayan recuperado.

## Ruta identificada

`CustomServerShare.<clinit>` llama `KovSec_com.classes7Init0(226)`. La tabla JNI
asigna los diez métodos de `native-methods.json`. `ShareOptions` conserva campos
blocked, blockRoot, blockCompany, blockId/blockIdValue, expiresAt, loginById/
loginByIdValue y useUuid/uuidValue. `ImportResult` contiene ok, message, meta y
serverJson. Estas estructuras no bastan para definir el formato exportado.

En `libkovsec.so`, la tabla `0x4af2f0` registra classes7Init0 en `0x216840`.
La tabla de clases parte de `0x75844`, índices de clase en `0x86298`, offsets de
cadenas en `0x772e4`, triples de métodos en `0x390420`. La clase 226 recuperada
coincide exactamente con CustomServerShare y diez entradas. El pool de cadenas
se encuentra en `0x429c38`, tamaño `0x856b8` (**546488** bytes), codificado con
XOR repetido de 8 bytes almacenados en `0x2d8e8`. El constructor aislado
`0x21670c` efectúa esa transformación. Se reprodujo estáticamente y con sus
instrucciones ARM64 originales, comparando todos los bytes.

`doubleDecrypt` apunta al wrapper **0x272f1c**. Este prepara referencias a un
paquete de la VM y llama a **vmInterpret**; no contiene una llamada demostrada
al cifrado estándar del archivo. En este wrapper se observan paquete 2 y
offsets `0x6966e`/`0x684c`. No son claves ni offsets del archivo de usuario.
El código de la VM y sus mecanismos de ejecución/protección no se ejecutaron.
No se modificaron ni inicializaron los controles de KOV-SEC.

El código nativo tiene PLT con entradas de **24 bytes**. La herramienta histórica
suponía 16 bytes y etiquetaba algunas llamadas de forma incorrecta. Se corrigió
`elf_inspect.py` para resolver ADRP/LDR contra relocaciones GOT. Ahora identifica
correctamente `memset`, `malloc` y `vmInterpret`, y se verificó la regresión de
los cuatro wrappers de AboWaged con su layout anterior.

## Contenedor KVS1

Estructura comprobada mediante sus límites, offsets y consumidores nativos:

1. Cabecera little-endian `<4s4I>`: KVS1, versión 1, manifest 1085 bytes,
   tabla 48 bytes, payload 2298887 bytes.
2. Manifest JSON con build_id, files y format. Incluye hashes de las bibliotecas
   KOV-SEC por arquitectura. Validar hashes no equivale a descifrar métodos.
3. Tres entradas `<IIQ>`: id, offset, longitud. Cubren el payload sin huecos.
4. Payload de paquetes y 64 bytes finales de firma. El loader menciona Ed25519,
   pero no se recuperó/verificó aquí la clave pública de esa firma.

| Paquete | Offset en payload | Bytes |
| --- | --- | --- |
| 0 | 0 | 1092588 |
| 1 | 1092588 | 13281 |
| 2 | 1105869 | 1193018 |

Separar los paquetes no los convierte en DEX ni recupera las instrucciones
virtualizadas. No se ha determinado si alguna transformación adicional depende
del contexto de ejecución. Evitar afirmar que basta una firma, nombre de app,
SHA o ID de dispositivo inventado para abrirlos.

Se inspeccionaron además las bibliotecas hexvpn, hexshare, load, uz y x. El
antiguo libhexvpn exporta cifrado Rust bajo un nombre HexVPN que no aparece en
el pool de referencias de esta clase. **No se demostró su uso por el exportador
actual**, por lo que no se adoptó esa receta como lector de archivos.

## Trabajo pendiente

Recuperar el cuerpo virtual de exportToDocuments/importFromUri y doubleEncrypt/
doubleDecrypt; resolver las cadenas y su segundo argumento; identificar la
extensión, las capas y los requisitos de contraseña reales; validar una
exportación autorizada completa contra referencia independiente y worker.
Hasta entonces no existe file_decoder.py ni ruta Cloud/bot añadida. C0 240,
C8 250, Server VPN 36/38 y C11 permanecen iguales. Los binarios, paquetes,
pool recuperado y cualquier dato de usuario no se publican en Git.

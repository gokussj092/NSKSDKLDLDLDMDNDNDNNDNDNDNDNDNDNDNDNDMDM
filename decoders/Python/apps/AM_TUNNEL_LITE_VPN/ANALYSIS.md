# Punto de continuación: AM build 63

**Este documento registra investigación pendiente, no una certificación del
catálogo.** Usar exactamente los hashes del manifest; no trasladar offsets a
otro APK por nombre o tamaño. No hay bloqueo de permisos del usuario.

## Material preparado

- Base APK SHA-256: `636f96d211266bb592d47ff0f63cb886e332cb312c99ef0fb48572c180065aed`.
- Paquete `app.vpn.amtunnellite`, versionName `AM`, versionCode `63`.
- Tres DEX raíz. Las clases críticas aparecen referenciadas en los IDs pero
  sus definiciones Java no están en la salida original. La inspección de
  `class_data_item` no encontró clases huérfanas recuperables directamente.
- `assets/.efuyxx.dex` mide 120758 bytes: stub con `file_size=428`, seguido de
  120330 bytes en la región enlazada. La región empieza con otro encabezado
  DEX cuyo tamaño declarado es 13900976, igual al DEX 1; su cuerpo no constituye
  un DEX completo listo para JADX. El archivo original falla el checksum DEX;
  no desactivar el control y presentarlo como un DEX recuperado.
- `assets/LIAPP.ini` identifica LIAPP `v5.1.1.190`. El manifiesto declara
  `com.liapp.x` como Application.

## Método nativo confirmado

`libputils.so`, SHA-256
`a0e7c704dbf8bde1ee5e05d230a0232e0c5ea3f75b4be01d6519993cfdf93890`:

| Rutina | Dirección | Evidencia |
| --- | --- | --- |
| `PUtils.pDecrypt` | `0x147ed4` | Hexadecimal → XOR → NewStringUTF |
| `hexToString` | `0x146550` | Conversión intermedia |
| `xorWithKey` | `0x1466d4` | XOR por índice módulo 12 |
| Datos iniciales de clave | `0xc4947` | Ocho bytes, seguidos del inmediato little-endian `0x5d506b66` |
| Guard local de certificado | `0x147c70` | Lee APK/RSA/certificado y compara su SHA-1 |
| `getSignatureSha1` | `0x147590` | Identidad local, no una petición HTTP |

La clave de formato es `4%PdXch>fkP]`. El oracle ejecuta la rutina XOR aislada,
con copia de `std::string` y memoria acotadas. Ocho salidas coinciden con los
bytes UTF modificados generados por DataOutputStream JDK. No se ha probado
un campo real extraído del catálogo que aún no está abierto.

### Paquete y firma: control local confirmado

`pDecrypt` llama al guard y compara el paquete con `app.vpn.amtunnellite`.
El guard admite los SHA-1 `5FED785CA69AEC41CE2C925E8C8A5A738A6DE276` y
`8F2A3D1AF1A88D527B8C7FC247EA2C1208308F3C`. El certificado del APK entregado
tiene este último SHA-1; SHA-256 del certificado:
`6ec7a52144782de25268ce82e73cf81ec6fb315bf6f768e6bc6c300c10b7d76f`.
Se comprobó por inspección del flujo y extracción del certificado; no se
ejecutó el guard completo en Android. El auxiliar Python reproduce la
transformación de campos sin depender de PackageManager ni modificar el APK.

Esto no demuestra que el servidor reciba o exija paquete, SHA o firma en
cabeceras. Tampoco el timeout demuestra autenticación. No añadir cabeceras
supuestas ni confundir el pinning TLS de `com.liapp.C/l` con identidad HTTP.

## Primera capa del protector recuperada

Wrapper ARM64 `libefuyxx.so`, SHA-256
`f09f2ab5e12d41836ed4ddd25022bfac7271432710462312cca7790accfaeb29`.
Su constructor busca el marcador `0806090107020301` a partir de `0x2800`.
En esta muestra está en `0x78b8`. El payload comienza ocho bytes después;
restaurar únicamente los cuatro bytes de magic `7f454c46` recupera un ELF de
**657452 bytes**, SHA-256
`fe2ee74275a21be8b6ff728d00761db8676fb729af2de4e455b672f500c7e5e6`.
`liapp_wrapper.py` comprueba ambos hashes y no ejecuta ninguno de los ELF.

Esto no desempaqueta el DEX ni elimina la protección de la aplicación.
El ELF recuperado contiene `JNI_OnLoad` en `0x82ccc`. Su sección `.text`
no abarca todo el código del segmento: inspeccionar también el rango
`0x7dbfc..0x8e810` directamente con `ElfImage.read/disassemble`.

Puntos inspeccionados para continuar, sin afirmar una receta completa:

- `0x11798`: stream XOR de bytes con estado inicial `seed ^ 0x94202191`,
  actualización de 32 bits `state = state * 214013 + 2531011`, byte de salida
  `(state >> 16) & 255`. Es código del protector, no del catálogo.
- `0x802b0..0x803a4`: descodifica metadatos y verifica relaciones entre enteros.
- `0x82460..0x82504`: deriva material MD5 a partir de una cadena formateada
  con tres enteros globales, `%8.8x%8.8x%8.8x`; ver la recuperación siguiente.
- `0x82580..0x829dc`: expansión de clave AES de 128 bits y procesamiento CBC
  dentro de la rutina del protector. La presencia de AES aquí no demuestra
  que `pdrv2.json` use esa misma receta.

## Arranque y metadatos LIAPP recuperados

La clase `com/liapp/x.java` está en **DEX 2**, no en DEX 1. Su `m63` arma
metadatos de versión, paquete, dataDir, sourceDir, nativeLibraryDir, minSdk,
targetSdk, flags, SDK, UID, release, debugger y serial, separados por `|`.
Llama a `m31(Context,String,String,int,int,int,Context,Application,Object)`;
la entrada nativa inspeccionada comienza en `0x83974`. La desofuscación literal
`k.m14` recorre unidades UTF-16 desde el final: XOR con estado inicial 124 y
`state = (state ^ index) & 63`. No se compilan las clases extraídas del APK.

Se recuperaron los **213 bytes** de metadatos del protector, SHA-256
`626ddbf5be13f9fb8e4d86062c5fcf5e8f3ecf147d509a657536ba80fa1b7a01`.
El Python estático y la rutina ARM64 original producen exactamente ese bloque
y supera la relación original entre los tres enteros. No es el catálogo.

Para este hash exacto, en aritmética de 32 bits:

1. `D50` parte de `0xa6038691 ^ 0xb3167321` y acumula XOR de CRC32 y tamaño
   ZIP de **1003 assets**. Excluye `.efuyxx.dex`, `dexopt/baseline.prof` y
   `dexopt/baseline.profm`. No leer ni publicar las configuraciones WireGuard.
2. `D4C = CRC32("app.vpn.amtunnellite") ^ 0xd6162568 ^ 63`.
3. `D48 = D50 ^ 0xd6162568 ^ 0x11308681` tras las simplificaciones del flujo.
4. Resultan `D48=0x6b534996`, `D4C=0xfebb5fab`, `D50=0xac75ea7f`.
   El bloque de cuatro bytes del asset en `0x220` se abre con el stream
   `0x11798` y D48: longitud 213. Los siguientes 213 bytes, desde `0x224`,
   se abren con D4C. Su primera palabra debe ser `D48 ^ D4C ^ D50`.

Los cinco flags recuperados son `113,113,4227077,0,0`. La Application original
es `prince.udp.vpn.activities.UDPApplication`; la Activity original es
`prince.udp.vpn.activities.SplashActivity`. Sus definiciones protegidas aún
no se han reconstruido. Los valores anteriores son material del protector,
no credenciales de servidor ni una receta para `pdrv2.json`.

Fuentes conservadas:

- `am_liapp_metadata.py`: recuperación estática, stdlib, hash exacto y límites.
- `am_liapp_native_probe.py`: checkpoint acotado de `0x7e018`. Lee solo las
  dos copias de APK verificadas en memoria; modela rutas, archivos `/proc`
  vacíos e identificadores de proceso. Acelera helpers de bytes/cadenas/CRC.
  Ejecuta LCG, inflater y comprobación de metadatos originales. Se detiene
  en `0x803b4`; **no ejecuta Android/JNI real ni arranca la aplicación**.
- `tests/golden/am_liapp_generate.py`: 4 vectores LCG, 3 CRC y un bloque de
  metadatos sintético obtenidos de las primitivas ARM64 originales, sin
  modelar esas primitivas. Las pruebas ordinarias no necesitan APK/SO.

### Checkpoint posterior, todavía experimental

`--buffers` continúa únicamente hasta `0x829e8`, antes de las comparaciones
posteriores de integridad/entorno. Conserva asignaciones y globals si se pide
una carpeta nueva. Ejecuta el AES del protector. El asset principal queda
idéntico al original; el buffer secundario mide 34289 bytes, SHA-256
`e49adb49f7878355c741d47cc2c962890871b35899ef4491ee61bab69a330cc1`.
Ninguno constituye un DEX reconstruido. No confundir que la emulación llegue
a ese checkpoint con que la app completa funcione o pase todos sus controles.

El secundario contiene 1680 registros con longitud corta, pero su contenido
no está descifrado. El camino `m31` para cadenas, `0x8411c..0x84328`, usa
`0x12968` y `0x12a9c`, además del contexto global D54/D58/D5C y offsets.
Una inicialización tentativa no produjo un inventario válido; no publicar
esas cadenas ni tratarlas como material de claves confirmado. El siguiente
trabajo es recuperar ese contexto y las definiciones originales o capturarlas
en un runtime Android autorizado. No basta añadir identidad a la URL.

`libpdr.so` es un ejecutable Go con `main.main`, sin JNI exportado. No se ha
hallado evidencia de que participe en la apertura del catálogo; no tratarlo
como lector únicamente por el nombre.

## Sobre exterior y fuente

`pdrv2.json`: SHA-256
`3afd30a15d97f15105834c1f6a36fb8e07405d351e4bf23d1371546413c688d3`.
Base64 estricto, 117160 bytes descodificados; el tamaño no corresponde a un
CBC directo sin cabecera. Pruebas exploratorias con recetas de otras familias
no produjeron un documento válido; ninguna se incorpora a producción.
No asumir un algoritmo por alineación, cadenas aisladas o por el nombre AES.

El enlace de `README.md` fue extraído del inventario, todavía sin recuperar
su consumidor protegido. GET HTTPS produjo `TimeoutError: The read operation
timed out`. No se puede inferir HTTP 200/404, autenticación ni funcionamiento
real del servicio a partir de ese resultado.

Próximo paso: recuperar la clase de apertura y el esquema completo; después,
paridad independiente con el catálogo inicial, respuesta remota válida, CLI y
worker antes de habilitar el proveedor. Se pueden usar un DEX recuperado de
forma autorizada o una edición de la app sin este empaquetado como evidencia
adicional; el alcance actual sigue siendo offline, con el modelo de emulación
limitado descrito arriba. No hay una imagen/runtime Android disponible en este
entorno y no se certifica arranque, DEX completo ni solicitud de red de la app.

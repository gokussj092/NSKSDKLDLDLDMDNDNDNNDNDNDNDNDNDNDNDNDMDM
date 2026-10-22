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

La clave de formato es `4%PdXch>fkP]`. El oracle ejecuta la rutina XOR aislada,
con copia de `std::string` y memoria acotadas. Ocho salidas coinciden con los
bytes UTF modificados generados por DataOutputStream JDK. No se ha probado
un campo real extraído del catálogo que aún no está abierto.

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
  con tres enteros globales; aún falta reconstruir cómo se obtienen.
- `0x82580..0x829dc`: expansión de clave AES de 128 bits y procesamiento CBC
  dentro de la rutina del protector. La presencia de AES aquí no demuestra
  que `pdrv2.json` use esa misma receta.

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
adicional; el alcance actual sigue siendo estático/offline.

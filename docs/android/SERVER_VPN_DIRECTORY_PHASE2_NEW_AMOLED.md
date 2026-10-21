# SP-DECODE Android — fase 2: «Nuevo» local y diálogos AMOLED

## Qué se añadió

**Sin actualizar la API, ni el catálogo remoto ni los decodificadores.**
Se mantiene el PR #96 en la rama
`feat/austroplus-vpn-13-0-1-decoders`.

### Etiqueta «Nuevo» para nuevos proveedores VPN

- Se registra localmente el conjunto de IDs de un **catálogo ya verificado**
  (`ServerVpnCatalogRepository`). El primer catálogo válido forma la línea
  base: una primera instalación **no** muestra todos los proveedores como nuevos.
- Cuando un catálogo remoto verificado incluye un ID no visto antes, se guarda
  la **hora del teléfono** (`System.currentTimeMillis()`) de la primera detección.
  La misma detección funciona desde la descarga manual, el watch visible o la
  recuperación periódica `WorkManager`. No se usa la fecha del servidor ni
  el huso horario del VPS.
- La etiqueta localizada aparece en la tarjeta del proveedor durante
  **2 horas (7 200 000 ms)**, y desaparece al vencer el tiempo incluso si
  la pantalla Server VPN permanece abierta. Las visitas y refrescos no reinician
  el plazo; si el usuario sale de la pantalla y vuelve, se comprueba la marca
  original.
- Nunca se vuelve a armar una etiqueta por reordenación, cambio de nombre,
  desactivación del proveedor, cierre/reapertura o simple consulta del mismo
  catálogo. Tras caducar, se elimina la marca temporal y se conserva el ID
  conocido.
- Un cambio manual del reloj del teléfono puede adelantar la expiración;
  un retroceso detectado invalida la marca en vez de prolongar el plazo.
  Los cambios de zona horaria no alteran la diferencia entre milisegundos.
- El mecanismo conserva únicamente IDs públicos y marcas locales; no comparte
  información del dispositivo, contraseñas, archivos ni resultados.

### Etiqueta «Nuevo» para funciones de la aplicación

- La función reutilizable `ServerVpnNewBadges.featureRemaining(featureId)`
  admite una clave **única y estable** por funcionalidad.
- Está conectada a `server-vpn-manual-refresh-v1`, para marcar el botón
  de consulta manual como función recientemente introducida.
- Para una próxima función, declarar un ID nuevo y mostrar
  `ServerVpnNewTag()` solo mientras `featureRemaining` devuelva tiempo
  restante. No reutilizar IDs anteriores ni reiniciar el contador por apertura.
- Las nueve traducciones actuales están en
  `values*/server_vpn_directory_strings.xml`.

### Diálogos y alertas con tema AMOLED

Antes, `CloudLegalConsentDialog` se montaba **fuera** del
`MaterialTheme` local de `SpDecodeApp`. Por ello recibía los colores
por defecto (superficies claras y acentos violetas).

- `SpDecodeAmoledTheme` ahora envuelve **todo** `MainActivity.setContent`,
  inclusive Splash, consentimiento legal, contraseñas Cloud y formularios de
  credenciales.
- `SpDecodeApp` utiliza el mismo tema compartido. Fondo puro `#000000`,
  texto claro y controles sin morados por defecto.
- Los `AlertDialog` de términos/privacidad, contraseña Cloud, HC/HWID,
  credenciales privadas, errores, confirmaciones de historial y ajustes usan
  explícitamente fondo negro, texto blanco/legible, elevación tonal nula.
  También se actualiza el modal de progreso de descifrado.
- Se mantienen las confirmaciones explícitas, consentimiento y políticas
  de pantalla segura de los diálogos que manejan secretos.

## Compatibilidad y publicación

- `android/app/build.gradle.kts`: se actualizan anclas del generador Cloud
  a la firma de `decodeText(userText:String,password:ByteArray?=null)` y
  el callback `onFailure={uri,cause->` ya existente. No cambia la API.
- Pruebas instrumentadas:
  `ServerVpnNewBadgesInstrumentedTest.kt`, junto a las de la fase 1.
- Antes de distribuir ejecutar el build Cloud y el pipeline de Play, comprobar
  manualmente consentimiento legal (primer inicio), sus vínculos externos,
  detalles y accesibilidad de diálogos, RTL y traducciones, y el contador de
  «Nuevo» con un catálogo previo y otro con un proveedor nuevo.
- **La adición de extensiones de archivo desconocidas sigue limitada por el
  catálogo de formatos del cliente.** Estas etiquetas no convierten Android en
  un descargador de decodificadores ni instalan código remoto.
- No se fusiona a `main`, no se despliega al VPS y no se publica APK/AAB
  hasta completar QA/CI y obtener autorización.

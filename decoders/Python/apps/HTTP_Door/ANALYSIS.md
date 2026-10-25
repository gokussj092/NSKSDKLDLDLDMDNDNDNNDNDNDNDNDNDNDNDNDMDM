# Evidencia HTTP Door 5.0

Análisis del APKS aportado por el usuario, 2026-10-24. Rama del PR #99 sobre
`cf6ba54473e272ae53ed0ad3f930144108c372cd`. No se ejecutó el APK ni se
modificaron controles de la aplicación. No se incluyen binarios o perfiles
reales en Git.

| Entrada | Bytes | SHA-256 |
|---|---:|---|
| HTTP Door_5.0.apks | 43338815 | `913687b3a9f927b614e8aac917b86e7c431502b07156439fc706cf9b738fa40a` |
| base.apk | 24729394 | `89a68ced6a70f390a04c85b20c46645cdcbabdc0aac3d796990e1b55da1b05c8` |
| classes.dex | 7981664 | `0bad37f02be5581b048869208dd1d48a903f278cb1cd6ba26a5a4866f52e776b` |
| classes2.dex | 8574892 | `4f99247766b089668672c31650f93e70d8c8b684b83fcdd3e5ee6330bdfabc82` |
| res/drawable/v2.png | 1004280 | `ea6fb429bdd33f2392bd518927ad71191a92164d69fd7deacfaf1cd50c75f889` |

Identidad del manifiesto: `com.httpdoor.vpn`, nombre HTTP Door, versionName
5.0, versionCode 5. PNG original de 1920×1920 identificado e inspeccionado;
no se publica icono en Server VPN porque no se identificó su catálogo.

## Formato observado

JADX 1.5.6 fijado por checksum terminó con **18 errores en DEX1 y 11 en DEX2**.
No se afirma descompilación completa. Las rutas relevantes se verificaron
también en Dalvik: `ConfigParser.convertDataToFile`, **379 instrucciones**, y
`convertInputAndSave`, **575 instrucciones**.

- Manifiesto: `ConfigImportFileActivity` recibe file/content y patrones `.kyz`.
- `ConfigParser.FILE_EXTENSAO = "kyz"`; `ConfigExportFileActivity` añade `.kyz`.
- `convertDataToFile`: `Properties.storeToXML` con comentario
  `Archivo de Configuracion` → `encodeInput` → `Cripto.encrypt`.
- `Cripto.encryptOrDecrypt`: `DESKeySpec(KEY_PASSWORD.getBytes())`,
  `SecretKeyFactory.getInstance("DES")`, `Cipher.getInstance("DES")`.
  `KEY_PASSWORD = "cinbdf665$4"`, primeros ocho bytes efectivos `cinbdf66`.
  DES-ECB/PKCS5Padding, ciphertext binario sin Base64 ni IV adicional.
- `convertInputAndSave`: `Properties.loadFromXML(decodeInput(...))` precede
  a validaciones de versión, protección/fecha, root, instalación, operador,
  HWID y preferencias. La clave no depende del usuario ni del dispositivo.
- `file.pedirLogin` controla credenciales de conexión. No debe presentarse
  como contraseña necesaria para descifrar el archivo. Se retienen los campos.
- SecurePreferences usa su propio AES para almacenamiento, independiente del
  archivo compartido. No se trasplanta esa receta a `.kyz`.

El lector conserva el XML exacto y las entradas individuales; el mapa separado
reproduce last-value-wins de Java. El parser canónico de CREEB combina pares
de referencias numéricas UTF-16, habituales en el XML Java, sin modificar
`raw_xml`. El JDK de referencia rechazó un emoji literal de cuatro bytes en
`Properties.loadFromXML`; los vectores de paridad usan referencias numéricas
como los exports Java. No se confunde una prueba sintética con un export real.

## Catálogo y enlaces

No se identificó catálogo incluido o remoto en las rutas de aplicación
revisadas. Los assets son geodatos de túnel, licencia y perfiles de arranque;
`res/raw/block.json` es una animación Lottie (`layers`/`markers`), no perfiles.
`pdnsd_local` configura DNS. `AppUpdater.doInBackground2` contiene únicamente
un GET genérico a `http://localhost:8000/update.json`, sin consumidor de
servidores identificado. **No se consulta localhost ni se registra como broker.**
Los enlaces Telegram/contacto, anuncios y Firebase no son fuentes de servidores.
El manifiesto no declara un esquema propietario de perfil; no se inventa
`kyz://` o `httpdoor://`. Los protocolos V2Ray comunes conservan sus rutas.

Las bibliotecas de túnel no son necesarias para verificar el DES Java. Un
intento del inspector Go existente rechazó libuz (ARM32 dentro del split
nombrado ARM64) y el pclntab de libgojni no coincidió con su diseño soportado.
No se afirma análisis nativo completo ni se cambian esos inspectores para
este formato puramente Java.

## Registro

Nueva ruta `.kyz` en C8 y bot; C0 congelado 240, C8 253, 25 overrides. Catálogo
de servidores conserva 45 fichas y sus controles. Se eleva la versión mínima
a 45 para que clientes con metadatos 44 reciban el formato nuevo. Se publica
`cloudSupported: true`, `offlineSupported: false`, sin credenciales de entrada.
Sin proveedor, descarga, fusión, despliegue, APK o C11. El script autónomo
es reproducible con `http_door_bundle.py`; sus funciones XML provienen del
código canónico, no de una segunda implementación mantenida por separado.

# Hex Custom — descarga de archivos en la nube

Estudio de cómo Hex Custom 10.6.7 (`com.hex.custom.jotchuast`) comparte
archivos `.hexcm` por la nube. Todo lo de abajo se verificó contra el
APK 10.6.7 y contra Firestore en vivo (2026-11-17). **No hay catálogo
HTTP de proveedor ni lista de archivos**: la nube es un buzón de
archivos sueltos, uno por clave.

## Resumen

- **Servicio:** Google Cloud Firestore (SDK 26.6.0 dentro de la app),
  proyecto **`hexcustom-d3bc9`** (también hay Realtime Database
  `https://hexcustom-d3bc9-default-rtdb.firebaseio.com` y bucket
  `hexcustom-d3bc9.firebasestorage.app` en la configuración, pero los
  archivos van a Firestore).
- **Colección:** `archivos` (de `FileRepository.COLECCION`, que viene de
  `AppConfig.s_archivos()`).
- **Documento:** la clave que se muestra al usuario, p. ej.
  **`HexCustom-BoKo2Q5gQR`** — literalmente el ID del documento.
  Formato validado en la app por la regex de
  `AppConfig.u_hexcustom_a_za_z0_9_10()` (`HexCustom-` + 10 caracteres
  alfanuméricos; el prefijo visible es `HexCustom-`, distinto del
  `PREFIJO` interno `hexcustom` de `FileRepository`).
- **Autenticación: ninguna de usuario.** La lectura funciona con solo
  la clave de API de Firebase del proyecto (la que va en la
  configuración de la app). No hace falta cuenta, login, token de
  Firebase Auth ni dispositivo: la regla de Firestore permite leer
  documentos de la colección `archivos` con la API key. (Otras
  colecciones devuelven 403 con la misma key, así que el permiso es
  específico de `archivos`.)
- **Formato de lo descargado:** el documento es un `.hexcm` HXS3 tal
  cual, guardado como bytes. Al abrirlo se usa el mismo decodificador
  de archivos (en este caso, rama sin contraseña, flags `0x00`).

## Clases implicadas (DEX)

- `com.hexapplications.hexvpn.cloud.FileRepository` (singleton `INSTANCE`):
  - `generarId()` — genera el sufijo de 10 caracteres (alfabeto de
    `AppConfig.s_abcdefghijklmnopqrstuvwxyzabcdefghijklmn()`,
    `SecureRandom`).
  - `reservarId(nombre, tipo, bytes)` — reserva el documento en una
    **transacción** Firestore (falla con `IdOcupadoException` si el
    documento ya existe).
  - `subirArchivo(bytes, nombre, tipo)` — sube el archivo.
  - `obtenerArchivo(clave)` — lee el documento por su clave.
  - `getFirestore()` — instancia `FirebaseFirestore`.
  - Los cuerpos de `generarId`, `reservarId`, `subirArchivo`,
    `obtenerArchivo` y `getFirestore` son **abstractos en el DEX**:
    están implementados en código nativo protegido por KovSec
    (`libkovsec.so` / `libkovsecvm.so`, inicialización
    `KovSec_com.classes12Init0`). Por eso los nombres de colección y
    campos no se ven como literales en el DEX: salen de
    `AppConfig.s_*()` (cadenas descifradas en runtime).
- `com.hexapplications.hexvpn.ui.servers.CustomServerShare`:
  `uploadToCloud(...)`, `importFromCloud(ctx, clave)`,
  `importFromBytes(...)`, `normalizeCloudId(...)`, `buildExport(...)`,
  `sign(...)`, `doubleEncrypt(...)` / `doubleDecrypt(...)`,
  `getDeviceId(...)`. Estados de subida: `CloudExportState`
  (`Uploading` / `Done` / `Failed`).
- Las cadenas de `AppConfig` (`s_archivos`, `s_hexcustom`,
  `u_hexcustom_a_za_z0_9_10`, …) están ofuscadas (KovSec); los valores
  de arriba se confirmaron por el comportamiento en vivo, no por
  literales estáticos.

## Endpoint (Firestore REST v1)

Equivalente REST de lo que hace el SDK dentro de la app al importar:

```
GET https://firestore.googleapis.com/v1/projects/hexcustom-d3bc9/databases/(default)/documents/archivos/<clave>?key=<firebase_api_key>
Accept: application/json
```

- `<clave>`: la clave tal cual se comparte, p. ej. `HexCustom-BoKo2Q5gQR`.
- `<firebase_api_key>`: la clave de API web de Firebase del proyecto.
  **No se incluye en ningún entregable**: es la que la propia app
  lleva en su configuración (`google-services`, dentro de
  `resources.arsc` del APK). Quien replique la descarga debe extraerla
  del APK o usar la de su propio proyecto Firebase. En
  `Hex_Custom_10.6.7.py` se pasa con `--firebase-key` y nunca se guarda.
- Sin cabecera `Authorization`: no hay token de usuario.

Respuestas observadas:

| Caso | HTTP |
|---|---|
| `archivos/HexCustom-BoKo2Q5gQR` (existe) | **200** con el documento |
| `archivos/hexcustomBoKo2Q5gQR`, `archivos/hexcustom-BoKo2Q5gQR`, `archivos/BoKo2Q5gQR` (variantes del ID) | 404 `NOT_FOUND` |
| `hexcustom/...`, `files/...` (otra colección) | 403 `PERMISSION_DENIED` |

## Campos del documento

Documento `archivos/HexCustom-BoKo2Q5gQR` (creado 2026-11-16T18:24:39Z):

| Campo | Tipo Firestore | Valor (ejemplo) |
|---|---|---|
| `contenido` | `bytesValue` (Base64) | el `.hexcm` completo (6.958 B) |
| `nombre` | `stringValue` | `FastDNS.hexcm` |
| `tipo` | `stringValue` | `application/octet-stream` |
| `tamano` | `integerValue` | `6958` |
| `creado` | `integerValue` | `1794853479291` (ms epoch) |

Decodificando `contenido` (Base64 → bytes) se obtiene un `.hexcm`
HXS3 válido. En este caso: flags `0x00` (sin contraseña), salt distinta
a la del archivo que Pedro envió por otro canal.

## Verificación en vivo (2026-11-17)

1. `GET archivos/HexCustom-BoKo2Q5gQR` → HTTP 200, `contenido` 6.958 B.
2. El contenido descargado abre con el decodificador 10.6.7 (rama sin
   contraseña): perfil **FastDNS**, serverType 19,
   `test.hexapps.app:53`, empresa OXXO CEL, país mx.
3. Comparado con el archivo `FastDNS_nube_HexCustom-BoKo2Q5gQR_1_r6pe.hexcm`
   que envió Pedro (misma clave, 6.958 B): **mismo perfil, distinto
   archivo**. Solo difieren `meta.exportedAt` (1794853478508 en la nube
   vs 1794853472138 en el archivo de Pedro) y `signature`, y la salt /
   nonces (el sellado usa valores aleatorios). Es decir, la nube
   guarda una re-exportación del mismo perfil hecha ~6 segundos
   después, no una copia byte a byte del archivo de Pedro.
4. La descarga también funciona desde `Hex_Custom_10.6.7.py`:
   `--cloud-key HexCustom-BoKo2Q5gQR --firebase-key <clave>` → perfil
   FastDNS.

Evidencia guardada en `work1067/`: `cloud_doc.json` (respuesta completa
de Firestore), `cloud_contenido.bin` (el `.hexcm` descargado),
`cloud_probe.py` (script de la prueba).

## Subida (no probada)

El flujo de subida (`uploadToCloud` → `reservarId` en transacción →
`subirArchivo`) escribe el mismo documento con los 5 campos de arriba.
**No se probó escribir**: para no crear ni modificar documentos en el
Firestore de otro. La transacción rechaza el ID si ya existe
(`IdOcupadoException`), así que subir con una clave existente falla sin
sobrescribir. La escritura puede tener reglas distintas a la lectura;
sin probarla no se puede afirmar que sea pública.

## Cómo se usa la clave

1. Quien comparte exporta su perfil en la app → la app genera un ID
   (`HexCustom-` + 10 caracteres aleatorios), sube el `.hexcm` a
   Firestore y muestra la clave al usuario.
2. Quien recibe escribe la clave en la app (o pega el texto; la app la
   normaliza con `normalizeCloudId`) → `importFromCloud` hace
   `collection("archivos").document(clave).get()` → toma `contenido` →
   lo importa como archivo `.hexcm` (mismo `nativeOpen`, misma KDF).
3. La clave **no es una contraseña del archivo**: no cifra ni
   descifra nada. El `.hexcm` descargado puede venir con o sin
   contraseña propia (el de FastDNS viene sin contraseña; si viniera
   con contraseña, la app la pediría al importar, igual que con un
   archivo local).

## Límites

- No hay endpoint de catálogo ni de listado: no se puede enumerar qué
  archivos hay en la nube; solo se descarga por clave exacta conocida.
- No se verificó la subida ni las reglas de escritura.
- Los métodos nativos KovSec impiden ver estáticamente los detalles
  internos (nombres exactos de campos ya confirmados por la respuesta
  en vivo, pero no, por ejemplo, si `reservarId` escribe campos
  adicionales antes de la subida completa).

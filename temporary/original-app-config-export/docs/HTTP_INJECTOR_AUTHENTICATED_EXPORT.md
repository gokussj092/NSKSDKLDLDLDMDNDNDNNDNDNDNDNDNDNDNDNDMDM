# HTTP Injector: Open.ehi y corrección del MAC exterior

Fecha: 2026-10-27, America/Tijuana. Continuación de la misma rama temporal,
cuenta Goku y repositorio migrado. Producción, Android, API y VPS sin cambios.

## Diagnóstico demostrado

El importador original usa un carrier `Base64(IV):Base64(MAC):Base64(ciphertext)`.
Verifica **HMAC-SHA256 sobre `IV || ciphertext` antes de descifrar AES-CBC**.
El lector Python existente ignora ese MAC. El primer exportador experimental
conservaba el segmento original aun cuando cambiaba el ciphertext.

Se recuperó la derivación de 48 bytes mediante PBKDF2-HMAC-SHA1, 5000
iteraciones: los primeros 16 coinciden con la clave CBC ya soportada y los
32 restantes verifican los MAC de **ambos originales**. El APK aporta su
certificado público; no se versionan certificados ni claves derivadas.

| Material | MAC exterior | Adler-32 y AEAD interior |
| --- | --- | --- |
| Original anterior / A | Válido | Válidos |
| Open.ehi del propietario | Válido | Válidos |
| B/C/D/E anteriores | **Inválido** | Válidos |
| FLAG_ONLY / OUTER_NONE_ONLY anteriores | **Inválido** | Válidos |

La relación con el mensaje de versión se comprobó en el importador recuperado:
su excepción `GeneralSecurityException` se convierte, para un contenedor EHI
reconocido, en el código `f15405` de la inspección parcial (clase original
`com.google.android.gms.common.internal.ᔫ`). La presentación usa ese código
para elegir el mensaje de versión antigua/nueva. El texto no identifica
exclusivamente un cambio real de `configVersionCode`.

Así queda demostrada una causa suficiente de rechazo de los seis archivos
modificados: el MAC desactualizado. No se afirma que fueran sus únicos
problemas, ni que corregirlo apruebe automáticamente el desbloqueo o HTML.
Reporte reproducible: `results/ehi_carrier_diagnosis_2026-10-27.json`.

## Lo que aporta Open.ehi

SHA-256 `54c9e0cb281661e62b69c997085da0d753a3abd65d383c35a0c5704438563b0a`,
18952 bytes. Versión exterior **244**, interior **0**, IV estándar índice 4,
`isConfigLock = false`, modos exteriores `"[\"none\"]"`.

El JSON exterior **omite `configSalt`**. El codec de campos usa en ese caso
el valor predeterminado existente, `EVZJNI`; el master key conserva la ausencia
del campo y no recibe ese valor artificialmente. El lector del laboratorio
anterior rechazaba esta muestra con `UNSUPPORTED_FIELD_SALT`; queda corregido.
Su reencriptación sin cambios vuelve a producir **todos los bytes originales**.

El archivo abierto también contiene claves concatenadas desconocidas. Su
presencia no demuestra otro fallo de descifrado ni autoriza eliminarlas.
Se conservan los campos y tipos completos. Las conexiones de las dos muestras
son distintas y **no se copian** conexiones de Open.ehi al archivo anterior.

No hay `configMessage` en Open.ehi. El nuevo escritor permite añadir únicamente
ese campo conocido, respaldado por el modelo `Profile` recuperado y por la
muestra anterior. Si ya existe, sustituye su contenido. No inventa flags ni
otras estructuras para habilitar la nota.

## Hash de bloqueo: no copiar el interior

Las dos relaciones siguientes se verifican exactamente contra las muestras:

- Original bloqueado: `SHA256(lockModes || configSalt)`.
- Open.ehi: `SHA256(configIdentifier || lockModes)`.

El exportador recuperado confirma ambas ramas según el estado de bloqueo.
El candidato abierto usa **identifier seguido de los modos**, no el hash
interior ni la fórmula de la rama bloqueada. Se valida primero la regla del
archivo fuente y se rechazan contextos desconocidos. No se selecciona una
fórmula únicamente por el número de versión.

En D/E se conservan la sal explícita y los tokens de conexión originales;
se rederiva la clave ligada a los metadatos. Queda por probar si el importador
mantiene el acceso editable y utiliza correctamente esos tokens en este estado.
No se mezclan ambos modelos completos ni se cambian hosts/puertos/credenciales.

## Recuperación reproducible del APK

`recover_ehi_apk_probe.py` acepta el ZIP/APKS aportado y exige los hashes del
APK base y las tres bibliotecas ARM64 auditadas. Extrae dos ELF interiores
mediante la cabecera RC4 y el XOR del wrapper, y expande el pool **Zstandard**
de `libdatajar.so`. La clave ligada al paquete abre con **SM4-ECB** los primeros
128 KiB de cinco DEX. Se conservan sus bytes y checksums sin reescribirlos.

Los cinco DEX coinciden con su **Adler-32 almacenado**; su SHA-1 almacenado no
coincide. No se presenta esa discrepancia como una verificación pasada. La
primera extracción incompleta, anterior a expandir Zstandard, producía punteros
de anotaciones inválidos y agotamiento de memoria en JADX. Se conserva fuera
de git como diagnóstico; **no es la fuente final de la derivación**.

La extracción completa permitió leer el carrier, la derivación de claves, el
hash, el límite de 500000 bytes y el manejo de errores. JADX 1.5.6 termina con
167 errores globales y quedan métodos VM/nativos: no se afirma decompilación
perfecta. Los resultados clave se contrastan contra los binarios reales.

Referencias primarias de investigación: [Quarkslab y DxFx](https://blog.quarkslab.com/dji-the-art-of-obfuscation.html)
y [AesCbcWithIntegrity de Tozny](https://github.com/tozny/java-aes-crypto/blob/master/aes-crypto/src/main/java/com/tozny/crypto/android/AesCbcWithIntegrity.java).
No se asume que sus formatos generales sustituyan a la evidencia de este APK.
Los APK, DEX recuperados, código del proveedor, certificados y claves permanecen
privados. Solo se versionan nuestras herramientas y resultados sin secretos.

## Nuevos archivos para el propietario

| Archivo | Cambio |
| --- | --- |
| A_REWRAP_ORIGINAL.ehi | Control anterior idéntico |
| B_NOTE_TEXT_HMAC.ehi | Solo nota de texto, bloqueos originales conservados |
| C_NOTE_HTML_HMAC.ehi | Solo HTML, bloqueos originales conservados |
| D_ACCESS_HMAC_CANDIDATE.ehi | Hash abierto recalculado y flag falso |
| E_ACCESS_HTML_HMAC_CANDIDATE.ehi | D más HTML |
| owned_open/O_A_OPEN_REWRAP.ehi | Open.ehi idéntico |
| owned_open/O_B_OPEN_TEXT.ehi | Añadir nota de texto al abierto propio |
| owned_open/O_C_OPEN_HTML.ehi | Añadir HTML al abierto propio |

Las ocho muestras pasan Adler-32, HMAC exterior, CBC/XXTEA y AEAD interior.
OpenSSL/cryptography verifica independientemente los HMAC y las dos capas CBC;
libsodium verifica los tags XChaCha. Argon2id sigue con argon2-cffi.

El estado al generar esta tanda era pendiente para Android. El siguiente
reporte manual sustituye ese estado inicial; no modifica los hashes ni los
resultados criptográficos históricos de `ehi_authenticated_matrix_2026-10-27.json`.
B/C conservan las restricciones originales por diseño. No se generan nuevos
archivos Dark Tunnel con banner.

## Resultado manual posterior: A y E se importaron

El propietario informó: «Solo estos archivos si se lograron importar», y
nombró `E_ACCESS_HTML_HMAC_CANDIDATE.ehi` y `A_REWRAP_ORIGINAL.ehi`.
El reporte completo sin datos de conexión está en
`results/ehi_authenticated_manual_import_2026-10-27.json`.

| Caso principal | Importación según el propietario | Editor / banner / conexión |
| --- | --- | --- |
| A | Aceptada; control idéntico al original | No confirmados |
| B | Rechazada: configuración inválida o archivo dañado, descripción aproximada | No confirmados |
| C | Rechazada: configuración inválida o archivo dañado, descripción aproximada | No confirmados |
| D | Rechazada: configuración inválida o archivo dañado, descripción aproximada | No confirmados |
| E | **Aceptada** | **Editor y banner correctos; conexión no confirmada** |

Los tres controles `owned_open/` están comprendidos en la frase global, pero
no fueron nombrados individualmente. Se conserva esa incertidumbre: no se
declara demostrado un fallo del rewrap idéntico de `Open.ehi`. El propietario
no indicó en su primer mensaje el texto del error. En la aclaración posterior
describió «configuración inválida» o «configuración o archivo dañado», sin
recordar el texto exacto. Se registra como paráfrasis, no como una cadena
literal del importador. La versión/build usada y los hashes medidos en el
dispositivo siguen sin confirmar. No se atribuye el mensaje de versión de
la tanda anterior a estos nuevos rechazos.

En esa misma aclaración confirmó que **E permite editar la configuración y
muestra correctamente el banner**. Se valida manualmente este flujo para la
muestra entregada, SHA-256
`4cdec21427ee012b1b118207ab4606f4a38ae8be150050b672c6f07dc0bbc40f`.
No se extiende la aceptación a otros perfiles ni a una conexión VPN real.

Se verificaron otra vez los hashes de los cinco archivos entregados y sus
capas mediante el lector estricto y el auditor independiente: todos pasan.
Entre D y E, el **único valor JSON interior diferente es `configMessage`**;
el JSON exterior, salvo `configData`, es idéntico. Los bytes interiores solo
cambian en el token de esa nota. Ambos mantienen los mismos campos de acceso
y los demás campos de conexión. Cada reencriptación modificada utiliza sal
AEAD, nonce e IV CBC nuevos; esos bytes aleatorios no se mantuvieron constantes.

Esto justifica investigar la nota y sus validaciones en el estado abierto,
pero **no demuestra que la nota original cause el rechazo de D**, ni explica
por sí solo B/C. El funcionamiento del editor y del banner de E se respalda
por la prueba manual posterior, no por esta comparación local. La conexión
sigue pendiente. Se conserva E sin regenerarlo como referencia aceptada
para importación, edición y HTML. No se declara resuelto el exportador general ni se
introduce una corrección especulativa en los decodificadores productivos.

La causa anterior del MAC desactualizado sigue demostrada. La aceptación de
E confirma un avance real después de corregirla; los rechazos B/C/D muestran
que aún falta aislar otras condiciones del importador. Estado actual:
**E validado manualmente para importación, edición y HTML en esta muestra;
conexión, otros perfiles y rechazos restantes pendientes**.

## Reproducir

Checkout completo, Python 3.12, `requirements-ehi-lab.txt` y bibliotecas del
sistema libsodium/libzstd. Los destinos deben ser nuevos y estar fuera de git.

```bash
python temporary/original-app-config-export/scripts/recover_ehi_apk_probe.py \
  --apks /ruta/privada/HTTP_Injector_6.5.0.zip --output-dir /ruta/privada/apk-audit
python temporary/original-app-config-export/scripts/audit_ehi_carrier.py \
  --source /ruta/privada/original.ehi --owned-open /ruta/privada/Open.ehi \
  --apk /ruta/privada/apk-audit/base.apk --matrix-dir /ruta/privada/matriz-anterior \
  --output /ruta/privada/diagnostico.json
python temporary/original-app-config-export/scripts/create_ehi_authenticated_matrix.py \
  --source /ruta/privada/original.ehi --owned-open /ruta/privada/Open.ehi \
  --apk /ruta/privada/apk-audit/base.apk --output-dir /ruta/privada/matriz-autenticada
python -m unittest discover -s temporary/original-app-config-export/scripts -p 'test_ehi*lab.py' -v
python -m unittest tests.test_android_ehi_standard tests.test_android_ehi_complete_result -v
```

El CLI individual acepta `--apk` para verificar todo el carrier. Sin ese
argumento sigue permitiendo inspección/rewrap idéntico, y bloquea cambios.
El generador anterior con opt-in se conserva exclusivamente como reproducción
del defecto histórico.

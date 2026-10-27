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

**Importación Android, editor, banner y conexión: pendientes para esta tanda.**
Probar primero O_A y luego O_B/O_C; después A/B/C/D/E. B/C siguen restringidos
por diseño: sirven para aislar notas. D/E son candidatos de acceso editable,
sin aprobación previa a la prueba del propietario. No se generan nuevos
archivos Dark Tunnel con banner.

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

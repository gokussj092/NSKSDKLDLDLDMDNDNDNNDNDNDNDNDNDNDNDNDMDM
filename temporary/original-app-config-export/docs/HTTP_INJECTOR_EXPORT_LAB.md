# HTTP Injector — exportación experimental y pruebas A–E

Fecha: 2026-10-27, America/Tijuana. Cuenta GitHub **gokussj092 / Goku**.
Repositorio migrado de letras aleatorias, misma rama
`feat/temporary-original-app-config-export-lab`. Solo archivos del laboratorio;
sin cambios de producción, API, Android, VPS, builds ni merge a main.

## Material y versión

Se inspeccionó el adjunto `HTTP Injector_6.5.0.zip`, que contiene un APKS.
El manifiesto del APK base identifica `com.evozi.injector`, versión **6.5.0**,
build **244**. La muestra `.ehi` existente tiene **17656 bytes**, SHA-256
`600c0cafc2419aa59a1b3b4b259030af267d646c327e547a44fdce2ff54f05b7`.
Su metadato `configVersionCode` es **229**; no se afirma que haya sido exportada
por 6.5.0 ni se deduce una versión comercial de ese número.

El APK está protegido mediante un wrapper Secneo. Su `classes.dex` principal
visible mide 22176 bytes; JADX terminó con tres errores. Los DEX accesibles de
SDKs publicitarios no contienen el importador real. No se recuperó el código
protegido principal ni se ejecutó Android. La evidencia de las capas del archivo
procede de la muestra autenticada y del lector existente, no de un supuesto
importador decompilado por completo.

## Formato observado y preservación

1. Dos slots Java UTF con sendos valores de ocho bytes; se preservan sin
   reinterpretar sus strings, su versión ni la fecha de creación.
2. Longitud del ciphertext como entero big-endian de cuatro bytes y un checksum
   **Adler-32 del ciphertext** almacenado en ocho bytes big-endian.
3. AES-CBC exterior con clave y IV estándar del lector existente, índice 3.
4. Carrier `Base64(IV2):campo_intermedio:Base64(ciphertext2)`. Se conserva el
   campo intermedio exacto y el IV2 original.
5. Segundo AES-CBC y XXTEA con palabra de longitud; su inversa reproduce los
   bytes originales, incluido su relleno. Se preserva cualquier prefijo anterior
   al JSON y el JSON exterior completo sin normalización.
6. `configData` usa XOR con `configSalt`, hexadecimal **mayúsculo** observado,
   Base64 de alfabeto personalizado y orden invertido. No se eliminan bytes NUL
   al construir la exportación ni se transforman otros campos por heurística.
7. El contenido es un frame v1 de **Argon2id + XChaCha20-Poly1305**. Se conservan
   sus parámetros de coste; límites explícitos evitan costes descontrolados.
   Cambiar metadatos de bloqueo requiere derivar de nuevo la clave.
8. Se preserva el JSON interior completo, con tipos, escapes, payloads, strings
   JSON anidados y nombres de campos desconocidos, incluso los concatenados.

La prueba A vuelve a construir todas las capas y es **idéntica byte por byte**
al archivo fuente. Las variantes modificadas usan salt y nonce AEAD nuevos,
recalculan el tag, todas las capas externas, la longitud y el checksum. Los
parámetros de conexión no se descifran para serializarlos otra vez: sus tokens
originales se mantienen. El lector de presentación no es la fuente de exportación.

## Error reproducible corregido

El primer prototipo conservaba como opaco el slot de ocho bytes posterior a la
longitud. En la muestra, su valor coincide exactamente con `Adler32(ciphertext)`.
Al cambiar una nota o el cifrado, conservar ese valor produce una inconsistencia
matemática aunque el lector Python siga descifrando, pues este ignora el slot.

El laboratorio ahora verifica ese checksum **antes de descifrar** y lo recalcula
al exportar. Una regresión introduce un checksum desactualizado y exige rechazo.
Los siete archivos entregados ya tienen checksum correcto. Las primeras variantes
incorrectas no se entregan. No se afirma haber observado un rechazo de ellas
en la aplicación ni que este sea el único control del importador.

Los goldens históricos de solo descifrado contienen cero como placeholder en
ese slot. No se cambia su comportamiento ni el lector productivo. Los tests
de exportación preparan el checksum observado; otras variantes no se aceptan
mediante un fallback silencioso.

## Notas y candidato de acceso editable

La nota existente está en `configMessage`. Su capa propia transforma unidades
UTF-16 con XOR `EHIMSG`, después UTF-8 y Base64. Se implementó la inversa,
contrastada con el lector para texto BMP, no BMP y multilínea. B y C sustituyen
la nota anterior; no se agregan campos nuevos ni dobles comillas de un JSON
adicional alrededor del HTML. El banner reutiliza créditos y enlaces SP-DECODE.
Su apariencia, enlaces y efecto sobre el editor necesitan prueba en HTTP Injector.

La muestra tiene ocho restricciones en el JSON exterior, mientras el interior
ya contiene `lockModes = "[\"none\"]"`, otro `lockModesHash` de 64 caracteres y
`isConfigLock = true`. La expiración interior es cero y el operador está vacío;
estos campos se conservan. Los metadatos de ambos JSON difieren y no se fusionan.

D/E reutilizan **la pareja none/hash ya observada en el interior** para los dos
campos exteriores y cambian únicamente `isConfigLock` a `false` en el interior.
Se recalcula correctamente el cifrado ligado a esos metadatos. **No se conoce
el algoritmo del hash de bloqueos del importador.** No se inventa un hash ni
se presenta esa combinación como un desbloqueo aprobado: es un candidato de
diagnóstico que debe probarse en el APK adjunto. Puede existir una comprobación
adicional sobre la pareja hash/contexto que el roundtrip Python no reproduzca.

## Archivos entregados

| Archivo | Cambio |
| --- | --- |
| `A_REWRAP_ORIGINAL.ehi` | Reencriptación sin cambios; bytes idénticos al original |
| `B_NOTE_TEXT_ONLY.ehi` | Solo sustituir la nota por créditos en texto |
| `C_NOTE_HTML_ONLY.ehi` | Solo sustituir la nota por el banner HTML |
| `D_ACCESS_CANDIDATE.ehi` | Pareja none/hash observada + flag interior falso |
| `E_ACCESS_HTML_CANDIDATE.ehi` | Combinar D con el banner HTML |
| `diagnostics/FLAG_ONLY.ehi` | Solo el flag interior, sin cambiar las restricciones exteriores |
| `diagnostics/OUTER_NONE_ONLY.ehi` | Solo la pareja exterior, sin cambiar el flag interior |

Probar A primero. Después B/C, y finalmente D/E revisando **también** acceso al
editor y parámetros de conexión. Si D/E fallan o siguen bloqueados, los dos
diagnósticos separan el efecto del flag del efecto de los metadatos exteriores.
No se genera un enlace cloud, texto compartido ni URL de actualización inventada.
Todos los archivos, originales y JSON privados se conservan fuera de GitHub.

## Resultados locales y límites

- 14 regresiones nuevas de exportación EHI pasan, incluidas la reconstrucción
  exacta, Unicode UTF-16, tipos, campos desconocidos, tags alterados y checksum.
- Seis regresiones existentes del lector EHI y 32 de Dark Tunnel/política de
  banner pasan: **52 pruebas** en esta sesión.
- Los siete archivos pasan el lector Python existente. Su proyección de conexión
  descifrada conserva todos los campos fuera de la nota y del flag autorizado.
- OpenSSL/cryptography verifica 14 capas AES-CBC; libsodium verifica siete tags
  XChaCha20-Poly1305 y el plaintext completo. Argon2id sigue usando argon2-cffi,
  no se afirma tener un segundo backend independiente para esa KDF.
- Se comprobaron los siete Adler-32 y las diferencias exactas de ambos JSON.

**Importación original, editor, banner y conexión en HTTP Injector pendientes.**
La aprobación manual de HTTP Custom/Dark Tunnel no se transfiere a esta app.
Ver `results/ehi_export_matrix_2026-10-27.json` y `ehi_validation_2026-10-27.json`.

## Reproducción

Python 3.12, checkout completo del repositorio, entorno privado y libsodium
disponible en el sistema:

```bash
python -m venv /ruta/privada/ehi-venv
/ruta/privada/ehi-venv/bin/python -m pip install \
  -r temporary/original-app-config-export/scripts/requirements-ehi-lab.txt
/ruta/privada/ehi-venv/bin/python \
  temporary/original-app-config-export/scripts/test_ehi_export_lab.py -v
/ruta/privada/ehi-venv/bin/python \
  temporary/original-app-config-export/scripts/create_ehi_export_matrix.py \
  --source /ruta/privada/source.ehi --output-dir /ruta/privada/matriz-nueva
```

CLI individual de inspección segura o rewrap exacto:

```bash
python temporary/original-app-config-export/scripts/ehi_export_experiment.py \
  /ruta/privada/source.ehi --output /ruta/privada/control-nuevo.ehi
```

No se imprimen JSON, hosts, payloads, credenciales ni claves por la consola.
Los destinos deben ser nuevos y los archivos se crean con permisos 0600.

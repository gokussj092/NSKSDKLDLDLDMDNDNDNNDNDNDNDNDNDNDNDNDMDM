# HTTP Custom HCCFG 11/n13 — investigación pendiente, 2026-11-01

**0 de 2 archivos nuevos descifrados. No se ha actualizado ni certificado el
motor para HCCFG 11.** Se autenticó el JSON exterior HCX4 completo en ambos,
pero no las secciones interiores ni los perfiles. No hay JSON descifrado que
entregar. Un diagnóstico del envelope no satisface el criterio de cierre.

Conector Goku, repositorio `gokussj092/NSKSDKLDLDLDMDNDNDNNDNDNDNDNDNDNDNDNDMDM`,
rama `fix/http-jireh-current-method`, base `56e487631c7656ec88fbb609499212f6d37597e4`.
La selección actual son los archivos HTTP Custom aportados por el propietario.
Ultra y MM conservan despliegue pendiente; UT Loop y FlexNet siguen pendientes.
No se fusiona, despliega, publica APK ni ejecuta Actions manualmente.

## Dos muestras reales

| Archivo | Bytes | SHA-256 | Metadato n | Resultado |
| --- | ---: | --- | ---: | --- |
| XL-UNLIMITED.hc | 7114 | dd40ebc925714b67ad847cc571852b9e969f58a0ae3f16f939008bae31557362 | 921 | HCX4 autenticado; interior pendiente |
| XL-UNLIMITED1.hc | 4554 | 1899bc2c522f84a95daa9929469e448b62e71bcfbab8c12524e05e3107b4cede | 914 | HCX4 autenticado; interior pendiente |

Ambos: HCCFG, `b=11`, `c=s1`, `d=h1`, `e=n13`, `h=0`, bloque `p` con
campos `a/b/c`. Hay dos/una secciones cifradas en `j`, respectivamente; no se
cuentan como perfiles recuperados. Los valores de `n` son metadatos de los
archivos, no prueba de que se haya obtenido o ejecutado un APK build 921.

El lector existente autentica HCX4 con su clave y AAD actuales. Una segunda
apertura mediante libsodium XChaCha20-Poly1305 coincide en **todo el JSON
exterior** con PyCryptodome, no solo en los campos inventariados. Eso no abre
los datos interiores. La CLI actual termina con `UNSUPPORTED_SCHEMA` en ambos.
Aplicar experimentalmente la fórmula n11 cambiando únicamente a 11/n13 falla
la autenticación interior en los dos; no se incorporó ese intento al motor.

## Original verificado

[Google Play](https://play.google.com/store/apps/details?id=xyz.easypro.httpcustom)
publica HTTP Custom 8.0.10/914. Se obtuvo base y split arm64 de Aptoide,
comprobando los MD5 publicados y el certificado del base:

| Componente | Bytes | SHA-256 |
| --- | ---: | --- |
| base 914 | 13856421 | 88d6bef49cc7dc7a5ba8700036b58be33e6a08cb8f93241bd1c630cdb459ba93 |
| config.arm64_v8a 914 | 28095452 | 8df8f806f9f6ecdb6cf7de2a794c69ee944bbec42417f0023b12b674280854c5 |

Certificado SHA-256: `95dd433d7e4a0be02d55cc62553edcfc8f077fe780be5a7da7f861c2558dc181`,
igual al original 899. El APK base carece de SO: el split contiene
`libf2c.so`, `libruntime.so`, `libcodec.so` y `libpolicy.so`.
JADX del base 914 terminó con 176 errores generales y expone numerosas firmas
`native`; no se afirma una descompilación completa del código protegido.

## Diferencia relevante y límite actual

Se recuperaron registros JNI y 794 cadenas del cargador mediante emulación
ARM64 offline. El entorno JNI/Java fue modelado y se desviaron guardas locales
de integridad para inspeccionar funciones aisladas. Esto **no** es una
activación oficial, una atestación válida ni una importación Android real.

Evidencia del original 914:

- `Y105411430485629081.c`, registrado en `libf2c.so` a `0xc6aa64`, construye
  transcript y contexto. Con entrada pública sintética n13 llama a `d` con
  **familia 4**, no una supuesta familia 5. El transcript observado conserva
  `HCCFG\0paquete\0versión\0features\0build\0semilla` y el info empieza por
  `app-config|n13|...`. No basta para certificar las secciones nuevas.
- `Y105411430485629081$X10543032595375086114.a`, `0xc3977c`, devuelve falso
  para n11/n13 y verdadero para n12/n14, contrastando el selector de HWID.
- `Y105411430485629081.d`, `0xbad238`, concatena un argumento adicional al
  primer bloque antes de llamar al proveedor nativo. Falta contrastar todos
  los argumentos de una importación oficial con Extra Protection activa.
- La cadena 365 identifica `resolve(AppConfigExtraProtection, Continuation)`.
  Su referencia enlaza `L13080397374811600352` con `X7883584356322645360` y
  el parámetro `J8674700882135419902`.
- `J8674700882135419902.c`, `0xa16e80`, serializa sus tres cadenas en
  `a/b/c`; se observó con valores públicos sintéticos. Esa es la forma del
  bloque `p` de las dos muestras. Sus `b` decodifican a 384 bytes y sus `c`
  a 32; las longitudes por sí solas no prueban un algoritmo o una clave.
- El resolvedor depende de componentes Android, incluidos un componente con
  `KeyStore`/`PrivateKey`/OAEP/PSS y otro con `KeyPair`. La ruta completa de
  provisión, caché y renovación no se ha validado.

La [documentación oficial](https://eprodev.org/api/) describe
Extra Protection como activación online inicial con comprobación de seguridad
del dispositivo; después permite reapertura offline en el mismo dispositivo.
La API pública documentada genera archivos con una API key del creador; **no
se ha demostrado que esa API key sea una clave para descifrar estos archivos**.

**Falta material y evidencia de una activación/importación legítima de estas
muestras.** No hay Android/ADB/emulador conectado ni caché/grant de esa
activación disponibles en esta sesión. No se solicitó una activación al
proveedor, no se enviaron los archivos a la API y no se fabricó Integrity,
atestación, sesión o token. No hay evidencia de caída del servicio ni de un
rechazo HTTP del flujo oficial: no atribuirle un bloqueo remoto demostrado.

## Reproducción y continuación

Los originales nuevos siguen en los adjuntos privados del propietario:
`libfile_82ff74ac86f0819183b271054ca7cd49` y
`libfile_b618360407788191845e45063669c65d`.
El APKS 899 usado como referencia tiene SHA-256
`6dd69113336f8e4be825b0a5315ce174ed85239d67be6c2813bf5769c4b03caa`
y está conservado privadamente con su nombre original.
APK/SO, envelopes completos, estados de emulación y resultados privados
permanecen fuera de GitHub. Checkpoint privado persistente:
`HTTP-Custom-914-HCCFG11-private-checkpoint.zip`, 65084136 bytes, SHA-256
`7056e8be05f5a6098e1841ea4ea5480fcc7c3282984047483eddf15e211569b8`.
Incluye base/split914, muestras, probes y estado JNI para continuar sin
repetir la recuperación. No incluye un JSON interior descifrado.

Diagnóstico reproducible, desde la raíz:

```sh
python scripts/apk_analysis/http_custom_probe.py /privado/muestra.hc
python decoders/Python/apps/HTTP_Custom/HTTP_Custom.py /privado/muestra.hc
python -m unittest tests.test_http_custom_899 tests.test_hc_sip_new_variants tests.test_cloud_c2_hc tests.test_cloud_c0_inventory -v
```

El probe autentica solo HCX4, omite semilla/ciphertext/valores de `p` y emite
`decryptionVerified=false`. Para estas dos muestras termina con exit 3 y
`PENDING_EXTRA_PROTECTION`. No es un nuevo lector habilitado en Cloud.
La suite anterior pasa **33 pruebas** y la suite del worker pasa **19**.
Con las entradas reales se ejecutaron cuatro CLI: todas exit1 con stdout
vacío y `UNSUPPORTED_SCHEMA`; ambos bridges exit3/`DECODE_FAILED`, sin éxito
ni perfiles parciales. Los dos probes terminaron exit3 y omitieron los valores
privados de `p`. Se conserva intacta la implementación
de n11/n12 y los motores históricos. Es regresión sintética, no una nueva
validación real de esos formatos ni de HCCFG 11.

Para continuar: observar una importación/activación oficial exitosa de una de
estas muestras en un dispositivo autorizado; identificar el material que el
resolvedor entrega al codec y su vínculo con `p`; completar petición, sesión,
renovación y verificación de la respuesta cuando correspondan. Mantener
cualquier material privado fuera de Git, argumentos y logs públicos. Después
contrastar KDF y AAD de cada capa, autenticar todas las secciones/HPR1/sidecars,
leer todos los HPC1 y comparar el **JSON interior completo** entre referencia,
API, CLI y worker. Solo entonces habilitar 11/n13 y actualizar el manifiesto.
No habilitar n14 por analogía sin su propia evidencia.

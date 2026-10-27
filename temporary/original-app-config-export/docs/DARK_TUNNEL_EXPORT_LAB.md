# Dark Tunnel 1.0.26 — laboratorio de exportación y texto

Fecha: 2026-10-27 UTC. Rama: `feat/temporary-original-app-config-export-lab`.
Continuación autorizada después de HTTP Custom. Aplicación: `net.darktunnel.app`,
versión `1.0.26`, código `32`. **Compatibilidad de importación pendiente**.

## Origen y estado de las muestras

Se utilizó exclusivamente el conector de la cuenta **gokussj092**, en el
repositorio privado `gokussj092/NSKSDKLDLDLDMDNDNDNNDNDNDNDNDNDNDNDNDMDM`.
La rama migrada apuntaba al commit anterior del laboratorio HTTP Custom,
`9cafafeb9e8cb8a1f31be285467004dec393bba5`; no fue necesario reiniciar el trabajo.
El cambio de cuenta/repositorio no cambia la marca SP-DECODE ni sus créditos.

La referencia verbal «Hot Tunnel» se interpreta como Dark Tunnel por los
adjuntos. **HA Tunnel Plus `.hat` no se modificó ni se investigó en esta fase.**

Material disponible:

- APKS de Dark Tunnel 1.0.26: base y split ARM64 inspeccionados localmente.
- Una configuración `.dark` de **757 bytes**, SHA-256
  `761ed05803b4370e42682e1cc7094bb18dd7f9dd2ae5cc515ccd8b32e777bc53`.
  La copia del ZIP privado contiene esa misma muestra, no otra bloqueada.
- La muestra es VLESS **sin `encryptedLockedConfig`**. Su versión exportadora
  no figura en el JSON abierto y no se deduce del nombre del APK adjunto.
- **Falta un `.dark` bloqueado exportado realmente por la aplicación**, propio
  o autorizado. Los controles que creamos al envolver el JSON no cubren esa
  ausencia. No se solicitó ni se intentó una conexión a sus servidores.

Los binarios, las proyecciones legibles y el APK permanecen fuera de Git.
Los resultados versionados contienen hashes, recuentos y estados, sin conexiones.

## Hallazgos demostrados

| Hallazgo | Evidencia | Corrección en el laboratorio |
| --- | --- | --- |
| La muestra abierta no pasa por el lector productivo `.dark` | `DTDecryptor.execute` exige `encryptedLockedConfig` y devuelve `None` sin él; reproducido con el archivo real y un sintético | Leer también el contenedor abierto, conservando sus bytes JSON |
| La salida de presentación no sirve como fuente de exportación | `_normalize_for_json` elimina cada clave literal `Password` y transforma bytes; regresión sintética conserva el original en paralelo | No reconstruir desde esa presentación; conservar los MessagePack y bytes cifrados originales |
| Archivos y texto comparten el formato | Exportador `C4967.m11200`, importador `AbstractC5283.m11336`, escritura de archivo en `C4962`/`C4963` | Generar el mismo token `darktunnel://` en `.dark` y `.txt` |
| Base64 exterior URL-safe, sin saltos internos y con padding | `Base64.encode(bytes, 10)` | Usar ese transporte; aceptar también Base64 estándar al leer |
| El formato protegido moderno tiene dos capas y hojas cifradas | Go `E`, `Efromc`, `Efromctoe`, `util.Efroms/Efromi`; serializadores originales | Preservar bytes y reproducir AES-CFB128, sin padding añadido |
| CFB no contiene tag de autenticación | `crypto/cipher.newCFB` y framing; prueba de alteración | Informar igualdad criptográfica; nunca reportar «tag validado» |
| El VLESS cifrado contiene una configuración Xray, no otro JSON del modelo Kotlin | `C5102.mo11267` y `AbstractC0905.m5383`–`m5393` | Recuperar únicamente la plantilla completa representable; rechazar opciones adicionales |
| El nombre serializado del transporte distingue mayúsculas | Enum DEX `Lיˉ/י;`: `Tcp`, `Websocket`, `Grpc` | Corregir las abreviaturas iniciales del prototipo (`TCP/WS/GRPC`) antes de generar la entrega; no son los valores de `transportNetwork` |
| El modelo abierto no dispone de una propiedad de nota | Descriptor `C5080`, 12 propiedades, y modelos de conexión | No inventar campos HTML/nota en el JSON abierto |

La retirada de `Password` está demostrada como pérdida de información de una
proyección. No se afirma que haya provocado un rechazo de importación Dark
Tunnel: aún no existe un resultado manual del nuevo exportador.

El objeto abierto también contiene algunos nombres antiguos de DNSTT en una
sección SSH inactiva. El APK 1.0.26 serializa `dnsttUdpDnsHost`,
`dnsttUdpDnsPort` y `dnsttPublicKey`. No se renombraron automáticamente los
campos antiguos ni se descartó esa sección. Su efecto en versiones anteriores
queda fuera de este ensayo.

## Capas y preservación

| Capa | Formato |
| --- | --- |
| Transporte | `darktunnel://` + Base64 URL-safe del JSON UTF-8 |
| JSON abierto | `type`, `name` y objetos opcionales por tipo; conservar desconocidos |
| JSON protegido | `encryptedLockedConfig` contiene Base64 del siguiente cifrado |
| Cifrado exterior | AES-256-CFB128 → MessagePack con `LockedAppConfig` y `EncryptedLockedConfig` |
| Cifrado interior | AES-192-CFB128 → MessagePack con `InjectConfig`, `SshConfig`, `V2RayConfig` |
| Hojas | Campos `Encrypted*` binarios, cifrados individualmente con AES-192-CFB128 |

Claves e IV coinciden con `DTConstants` del lector existente y se comprobaron
en el binario adjunto. El IV fijo tiene 16 bytes. No se agregan IV aleatorios,
tags ni padding que la aplicación no espera. Los puertos de las hojas son
**texto decimal cifrado**, no enteros MessagePack dentro del cifrado.

`LockedAppConfig` conserva `VersionCode`, `VersionName`, `Message`,
`ConnectedMessage`, `Password`, `ExpiredAtTimestamp`, `HardwareIdList`,
`TunnelType` e `IsSshLocked`, incluidos sus tipos. `VersionName`, notas y
`Password` son **bytes**, no valores que deban serializarse automáticamente
como cadenas JSON. El laboratorio no interpreta ni publica ese `Password`.

En `rewrap`, el JSON, ambos MessagePack y cada binario permanecen idénticos.
La edición de un valor MessagePack sustituye solo su token; conserva incluso
codificaciones no mínimas de valores desconocidos. Una nota opcional sustituye
únicamente `LockedAppConfig.Message` y vuelve a cifrar el exterior. No cambia
el cifrado interior ni los datos de conexión.

En `unlock`, se materializan las conexiones y después se establece el campo
conocido `encryptedLockedConfig` a cadena vacía. El flujo Java crea `Ca` solo
cuando esa cadena no está vacía. **Vaciarla sin recuperar las conexiones
dejaría los valores de sustitución del exportador**, por lo que el laboratorio
no lo utiliza como un supuesto desbloqueo por booleano.

Este modo elimina expresamente las restricciones del contenedor reconocido,
incluidas contraseña, expiración y lista HWID. Solo debe usarse con muestras
propias o autorizadas. Su original privado conserva todos esos metadatos.
Si aparecen secciones o propiedades cifradas desconocidas, la conversión se
detiene; `rewrap` sigue preservándolas. No se elimina ni se elude una validación
remota, ni se afirma haber comprobado todas las restricciones en Android.

## Alcance del prototipo

- Formato abierto: preservación para los tipos del enum del APK.
- `rewrap`: contenedor moderno de dos capas, conservando secciones desconocidas.
- Desbloqueo SSH: recuperación de host, puerto, usuario, contraseña, payload,
  modo, proxy, SNI y DNSTT. Se comprueban tipos y banderas consistentes.
- Desbloqueo VLESS: plantilla exacta del APK para TCP/WS/GRPC y TLS/no TLS;
  preserva mux y opciones originales. Compara **todo el grafo Xray**, incluidos
  los tres placeholders originales, para impedir la pérdida silenciosa de
  rutas, inbounds, opciones TLS u otras instrucciones.
  Los valores JSON exactos son `Tcp`, `Websocket` y `Grpc`; dentro del Xray
  son `tcp`, `ws` y `grpc` respectivamente. No intercambiar estos enums.
- Formatos antiguos, otras aplicaciones, SSH_DNSTT/VMess/Trojan/Shadowsocks
  cifrados y Xray personalizado: no convertidos en este ensayo.
- Un archivo de un solo perfil por operación; no truncar ni seleccionar
  silenciosamente una línea de un archivo con varios perfiles.
- No integración de producción. Los dos primeros hallazgos preparan esa mejora,
  pero la API, Android, el lector y el router de textos siguen sin cambios.

## Matriz privada generada

| Archivo | Origen y propósito | Resultado local | Android |
| --- | --- | --- | --- |
| `A_rewrapped.dark` | Reexportar la referencia abierta | JSON exacto | Pendiente |
| `B_rewrapped_text.txt` | El mismo token de A para importar texto | Igualdad exacta con A | Pendiente |
| `C_open.dark` | Modo desbloqueo sobre la referencia ya abierta | JSON exacto; no había bloqueos | Pendiente |
| `D_open_text.txt` | El mismo token de C | Igualdad exacta con C | Pendiente |
| `E_reference_restored.dark` | Recuperar los valores de la referencia desde un contenedor artificial | Todos los campos activos efectivos iguales; secciones ajenas preservadas | Pendiente |
| `F_synthetic_ssh_open.dark` | Reconstrucción SSH con dominio reservado `.invalid` | Conexión sintética íntegra | Pendiente |

**A–D contienen el mismo token. No son cuatro pruebas independientes de
compatibilidad.** E incorpora explícitamente algunos defaults que la referencia
omitía: por eso mide más aunque su conexión efectiva coincida.

`controls/` contiene tres controles artificiales: VLESS envuelto, VLESS con
nota sustituida y SSH envuelto. Los dos controles VLESS conservan datos reales
de la referencia; son privados. **No fueron exportados por Dark Tunnel.**
El control con nota usa texto de créditos; no demuestra renderizado HTML.
No se traslada a Dark Tunnel el esquema de notas de HTTP Custom.

Si la fuente futura ya está cifrada, la matriz genera `E_note_rewrapped.dark`
en lugar de E restaurado. Eso no acredita automáticamente el origen de la fuente.

## Verificación realizada

- **25 pruebas nuevas pasan**, más 29 del laboratorio HTTP Custom y nueve del
  lector HTTP Custom: **63 en total**.
- CFB128 contrastado entre PyCryptodome 3.23.0 y cryptography 50.0.2, con ambas
  claves y longitudes 0/1/15/16/17/31/32/257/4097, más un vector NIST.
- **48 comprobaciones CFB independientes** en los tres controles generados:
  exterior, interior y 14 hojas por control. No son tags de autenticación.
- **Seis serializadores Go originales** ejecutados mediante Unicorn con valores
  sintéticos: app, SSH, inject, V2Ray, contenedor exterior e interior. Se permiten
  solo sus rangos y helpers de memoria; no se inicia Android/JNI ni la red.
- Nombres de enums corroborados en las instrucciones DEX originales.
- JADX 1.5.6 terminó con 111 errores en el APK completo (salida 3). Los cuerpos
  relevantes usados aquí están disponibles; no se considera decompilación
  íntegra exitosa. La prueba de serialización utiliza las instrucciones Go.
- Escritura exclusiva 0600, directorio nuevo para la matriz, errores públicos
  sin valores privados y preparación completa antes de escribir variantes.

El probe fija el SHA-256 del SO:
`dc70bfc8a4c50d874ae7361e40098fedaf96dd6157a9d6370718658fd820adfb`.
Los hashes del APKS/base y los resultados quedan en `results/dark_*`.

## Reproducir

Desde la raíz del repositorio, con Python 3.12:

```bash
python -m venv /ruta/privada/dark-venv
/ruta/privada/dark-venv/bin/python -m pip install \
  -r temporary/original-app-config-export/scripts/requirements-dark-lab.txt

/ruta/privada/dark-venv/bin/python \
  temporary/original-app-config-export/scripts/test_dark_export_lab.py -v

/ruta/privada/dark-venv/bin/python \
  temporary/original-app-config-export/scripts/create_dark_export_matrix.py \
  --source /ruta/privada/source.dark --output-dir /ruta/privada/matriz-nueva
```

CLI individual, sin imprimir el JSON ni las credenciales:

```bash
/ruta/privada/dark-venv/bin/python \
  temporary/original-app-config-export/scripts/dark_tunnel_experiment.py \
  /ruta/privada/source.dark --mode inspect

/ruta/privada/dark-venv/bin/python \
  temporary/original-app-config-export/scripts/dark_tunnel_experiment.py \
  /ruta/privada/source.dark --mode rewrap --output /ruta/privada/control.dark

/ruta/privada/dark-venv/bin/python \
  temporary/original-app-config-export/scripts/dark_tunnel_experiment.py \
  /ruta/privada/source.dark --mode unlock --output /ruta/privada/open.dark
```

Para texto, usar un destino `.txt`: contiene el mismo token. `--note-file`
permite reemplazar `Message` solo con `--mode rewrap` en una fuente protegida.
El formato abierto devuelve `OPEN_FORMAT_HAS_NO_NOTE_FIELD` ante esa opción.
No crea una nota ignorada por el importador.

El probe opcional requiere `requirements-native-probe.txt` y MessagePack.
Extraer localmente `lib/arm64-v8a/libgojni.so` del split ARM64 del APKS adjunto,
conservar los binarios fuera del repositorio y ejecutar:

```bash
/ruta/privada/dark-venv/bin/python -m pip install \
  -r temporary/original-app-config-export/scripts/requirements-native-probe.txt
/ruta/privada/dark-venv/bin/python \
  temporary/original-app-config-export/scripts/probe_dark_schema.py \
  /ruta/privada/libgojni.so
```

El probe depende de las herramientas de análisis ya existentes del repositorio;
no modifica esas herramientas y no necesita ejecutar la aplicación.

La comprobación del enum que detectó las abreviaturas incorrectas también es
reproducible con el APK base fijado por hash:

```bash
/ruta/privada/dark-venv/bin/python -m pip install androguard==4.1.4
/ruta/privada/dark-venv/bin/python \
  temporary/original-app-config-export/scripts/probe_dark_dex.py \
  /ruta/privada/base.apk
```

## Próxima validación manual necesaria

1. Importar A como archivo y B como texto en Dark Tunnel 1.0.26; confirmar que
   la referencia original también importa en esa misma versión.
2. Importar E, revisar host, puerto, UUID, SNI, transporte, mux y payload frente
   a la referencia, y comprobar que el editor permite cambios.
3. Importar F para comprobar el esquema SSH editable. Su host `.invalid` es
   deliberadamente sintético; no usarlo para una prueba de conexión.
4. Aportar una exportación **bloqueada real**, propia/autorizada, indicando
   versión y opciones de bloqueo utilizadas. Compararla con una exportación
   abierta hecha por la misma aplicación/configuración.
5. Repetir rewrap, texto, desbloqueo y nota de forma aislada sobre esa fuente.
   Registrar hash del archivo exacto y resultado observado; mantener cualquier
   credencial fuera de capturas, respuestas, logs y GitHub.

Hasta entonces el estado es **prototipo local verificado; compatibilidad con
la aplicación original pendiente**, incluida la validación real de desbloqueo.

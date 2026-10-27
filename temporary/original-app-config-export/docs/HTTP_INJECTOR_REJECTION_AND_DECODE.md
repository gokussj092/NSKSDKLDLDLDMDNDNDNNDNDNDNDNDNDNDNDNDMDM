# HTTP Injector: rechazo de variantes y auditoría de la salida

> **Informe histórico, superado parcialmente por Open.ehi:** se recuperaron
> el HMAC y su clave derivada del APK; los seis casos modificados anteriores
> fallan esa comprobación. Ver [diagnóstico y nueva matriz](HTTP_INJECTOR_AUTHENTICATED_EXPORT.md).
> Los hallazgos de tipos y TLS siguen vigentes; producción continúa sin cambios.

Fecha: 2026-10-27, America/Tijuana. Solo laboratorio temporal, misma rama,
cuenta Goku y repositorio migrado. No hay cambios en los decodificadores
productivos, Android, API, despliegues ni builds.

## Resultado real comunicado por el propietario

| Caso entregado | Resultado comunicado |
| --- | --- |
| A_REWRAP_ORIGINAL.ehi | Se importó |
| B_NOTE_TEXT_ONLY.ehi | Rechazo con error de versión |
| C_NOTE_HTML_ONLY.ehi | Rechazo con error de versión |
| D_ACCESS_CANDIDATE.ehi | Rechazo con error de versión |
| E_ACCESS_HTML_CANDIDATE.ehi | Rechazo con error de versión |
| diagnostics/FLAG_ONLY.ehi | Incluido en la referencia global a «los demás»; sin confirmación individual |
| diagnostics/OUTER_NONE_ONLY.ehi | Incluido en la referencia global a «los demás»; sin confirmación individual |

Reporte por nombres, sin hashes medidos otra vez en el dispositivo, captura
del mensaje ni build confirmado de la app que hizo la prueba. El APK aportado
es 6.5.0/244; no se atribuye ese build al ensayo manual sin confirmación.
El fichero `results/ehi_manual_import_report_2026-10-27.json` vincula nombres
y hashes del paquete entregado. El paquete anterior queda como **histórico
rechazado**, sin compatibilidad aprobada para archivos modificados.

## Qué demuestra A y qué sigue sin resolverse

A es idéntico al original en todos sus bytes. Su importación confirma el
baseline. No prueba que el importador acepte una modificación.

El auditor volvió a abrir los siete archivos entregados y verificó:

- La cabecera anterior a la longitud del ciphertext es idéntica al original.
- `configVersionCode` exterior continúa en **229**; el interior sigue en **0**.
- Los parámetros de Argon2id y la versión de AEAD no cambiaron.
- Adler-32 es válido y el JSON interior autentica con XChaCha20-Poly1305.
- Todos conservan el mismo segmento central del carrier. En las variantes
  modificadas el ciphertext sí cambia.

Por tanto, no hay evidencia de un cambio accidental del número de versión.
Esto **no descarta** otras reglas de compatibilidad del importador ni demuestra
que su mensaje describa literalmente el fallo interno. No se cambia 229 a 244
ni el 0 interior: hacerlo sin conocer la regla sería inventar una corrección.
Que B/C también fallen impide atribuir todos los rechazos al desbloqueo.

La capa AES exterior contiene tres segmentos Base64 separados por `:`. El
central decodifica a **32 bytes**. El lector productivo lo ignora; el primer
exportador experimental lo preservó como opaco aun al sustituir el ciphertext.
La biblioteca primaria [Tozny java-aes-crypto, AesCbcWithIntegrity.java](https://github.com/tozny/java-aes-crypto/blob/master/aes-crypto/src/main/java/com/tozny/crypto/android/AesCbcWithIntegrity.java)
documenta exactamente el orden `Base64(IV):Base64(MAC):Base64(ciphertext)` y un
HMAC-SHA256 sobre `IV || ciphertext`. Es una **hipótesis de investigación**
para esta muestra. No se recuperaron una clave, una coincidencia MAC válida
ni el uso de esa clase en el importador protegido de HTTP Injector.

Las búsquedas acotadas de material ya observado y constantes de los binarios
no permitieron verificar el segmento. El APK sigue protegido por Secneo; las
cadenas Java visibles en `libdatajar.so` no equivalen a un DEX recuperado ni a
ejecución del importador. No hay un diagnóstico definitivo del error Android.

El defecto confirmado en el laboratorio es **permitir modificaciones sin
resolver todas las comprobaciones del contenedor**. Su relación causal con
el mensaje de versión queda pendiente. No confundir el Adler-32 del archivo,
el posible MAC de CBC y el tag AEAD interior: son capas distintas.

## Corrección inmediata del laboratorio

`reseal()` ahora permite el control idéntico, pero rechaza modificaciones con
`MODIFIED_EXPORT_BLOCKED_UNVERIFIED_CARRIER_SEGMENT`. No produce otro archivo
para que el propietario repita un fallo ya conocido.

`create_ehi_export_matrix.py` exige `--reproduce-rejected-exports`, y el API
`generate()` exige `reproduce_rejected_exports=True`, para repetir el ensayo
histórico. Esa opción pasa `allow_unverified_middle=True` de forma explícita.
Los resultados conservan `carrier_integrity_verified: false`. Esto es una
protección contra diagnósticos engañosos, **no la solución del importador**.

## ¿La salida del decodificador es completamente correcta?

**No puede considerarse un JSON completamente interpretado ni reconstruible.**
La capa interior está autenticada, pero su proyección mezcla representaciones.
El auditor no imprime valores de conexión, credenciales, notas ni claves.

| Hallazgo | Evidencia y consecuencia |
| --- | --- |
| Campos principales legibles | Usuario, host, proxy, payload, SNI y contraseña pasan el codec conocido con la sal exterior. Esto verifica la transformación; no se conectó a los servidores. |
| Cadenas desconocidas conservadas | Varias claves concatenadas y sus valores ya existen así dentro del JSON autenticado. El lector los conserva cuando no reconoce el codec. No se demuestra que sean datos útiles, señuelos ni otro cifrado pendiente. No se dividen ni renombran. |
| `tlsVersion` con caracteres de control | El codec con la sal exterior produce un valor fuera de los nombres TLS reconocidos por el laboratorio. La misma cadena, con la sal predeterminada **EVZJNI**, produce **TLSv1.2** y vuelve a codificar exactamente el token original, incluido `?` como representación del padding Base64. Es un candidato acotado sólido; falta contrastar el ajuste en la app original. No se aplica esa sal a todas las cadenas. |
| Contraseña de texto mostrada como número | El dato descifrado es `str`. `FinalJsonSurface.body` / `_format_top_level_json` lo convierten a texto sin comillas; `ResultPresentation.parseInlineJson` puede interpretarlo como número. Se demuestra con una credencial sintética, sin publicar la real. |
| `lockModes` presentado como lista | En el JSON interior original es un **string que contiene JSON**. La misma conversión de presentación lo vuelve lista. La capa exterior tiene sus propios modos y hash diferentes. Un `none` interior no demuestra que el archivo esté abierto. |
| `isConfigLock: true` | Se conserva del JSON interior original. No se sustituye en producción ni se deduce acceso editable a partir de otro campo. |
| `configVersionCode: 0` en la salida | Ya es 0 en el JSON interior original. El 229 pertenece a la capa exterior, que no se incluye en esa proyección. No es por sí solo un fallo de descifrado ni prueba que haya que reemplazarlo. |

La prueba de tipos reproduce la regla relevante de la presentación con Python
y se contrasta con el código Kotlin leído. **No se ejecutó Android** ni se
afirma que sea una ejecución completa de Gson. Estos hallazgos de lectura no
causaron una reserialización en las muestras rechazadas: el exportador toma
los bytes originales de ambos JSON, no el texto mostrado por SP-DECODE.

`audit_ehi_decode.py` informa por campo el tipo original, si el lector lo
transformó, si pudo comprobarse el codec reversible y si la presentación
cambia el tipo. Los nombres desconocidos se sustituyen por índices en el
informe. El candidato TLS se informa por separado y no altera el documento.
La corrección productiva del lector/presentación sigue fuera de esta rama
experimental y requiere la autorización ya establecida para producción.

## Reproducción y comprobaciones

Desde la raíz del checkout completo, con las dependencias del laboratorio:

```bash
python temporary/original-app-config-export/scripts/audit_ehi_decode.py \
  /ruta/privada/original.ehi \
  --matrix-dir /ruta/privada/matriz-entregada \
  --output /ruta/privada/auditoria-nueva.json

python -m unittest discover \
  -s temporary/original-app-config-export/scripts -p test_ehi_export_lab.py -v
python -m unittest tests.test_android_ehi_standard tests.test_android_ehi_complete_result -v
```

Pasan **22 pruebas del laboratorio y 6 regresiones existentes**. Se comprueban
el bloqueo previo a escribir, el rewrap idéntico, la reproducción optativa, la
auditoría de versiones, los tipos, la selección TLS acotada, la conservación
de desconocidos y la ausencia de secretos en el informe. No se repiten ensayos
de Android ni conexiones de red, porque no se dispone de ese entorno.

Para continuar son útiles una exportación propia **sin bloqueos**, creada
desde la misma versión que hizo la prueba, y el mensaje exacto de rechazo con
versión/build. Permitirá comparar un control nuevo del exportador original,
sin asumir que elimina la necesidad de recuperar la comprobación pendiente.

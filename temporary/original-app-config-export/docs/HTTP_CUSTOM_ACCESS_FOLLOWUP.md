# HTTP Custom — acceso textual y prueba manual de seguimiento

Fecha: 2026-10-26, America/Tijuana. Solo laboratorio temporal.

> Seguimiento posterior: ambos candidatos `none` fueron rechazados por el
> propietario. La nueva referencia abierta y la migración de estructura están en
> [HTTP_CUSTOM_OPEN_LAYOUT_REFERENCE.md](HTTP_CUSTOM_OPEN_LAYOUT_REFERENCE.md).
> Los estados pendientes de este registro describen el momento de su creación.

## Evidencia manual recibida

El propietario probó el paquete privado entregado en `f908b869` e informó:

| Archivo | Importación reportada |
| --- | --- |
| `CONTROL_original.hc` | Correcta |
| `A_baseline_rewrap.hc` | Correcta |
| `B_note_only.hc` | Correcta |
| `C_url_only.hc` | Correcta |
| `CONTROL_previous_rejected.hc` | Falló |
| `D_access_only.hc` | Falló |
| `E_combined.hc` | Falló |

`results/manual_import_report_2026-10-26.json` conserva el reporte y los hashes
esperados del paquete. Los hashes no se volvieron a medir en el teléfono y el
build del dispositivo no se reconfirmó independientemente. La app objetivo del
paquete y del APK analizado es build 899. No se inventan capturas ni trazas.

**Causa aislada en esta matriz:** sustituir `main.g.a = "lock_all"` por el
booleano `false` causa el rechazo. A prueba que esta reconstrucción criptográfica
sí se importa; B/C prueban las ediciones individuales de nota y URL. No se puede
atribuir ya el rechazo común a esas ediciones individuales.

Esto no identifica por sí solo la excepción interna: falta distinguir coerción,
validación de tipo o de enum. Tampoco prueba conexión o actualización remota.
No se afirma que la serialización de 426 → 419 bytes del intento antiguo fuera
la causa; esa diferencia fue eliminada como variable en la matriz actual.

## Valor recuperado del APK

Se identificó la protección en `N1505908798552522241`: su campo `a` tiene tipo
`K12246845678248903666`, un enum con cuatro constantes. Su `v` es String y los
flags/listas coinciden con la estructura observada de protección.

Se recuperó la tabla de métodos nativos de `libf2c.so` ARM64 y se ejecutaron
sus instrucciones en Unicorn con una superficie JNI modelada, sin cargar la
biblioteca en el proceso anfitrión ni contactar servidores. Entrada fijada por
SHA-256:

`62804ffbad47f599ad0bbb71eec31fad41a4ea3a8eb45cee3410742a299af220`

El inicializador de enum `0x9c4bcc` proporcionó estos argumentos reales a sus
cuatro construcciones. El constructor nativo `0xa65e44` se ejecutó además de
forma aislada para verificar que guarda el tercer argumento como String en el
campo `a`:

| Constante | Ordinal | Valor textual almacenado |
| --- | --- | --- |
| `NONE` | 0 | `none` |
| `LOCK_ALL` | 1 | `lock_all` |
| `LOCK_PAYLOAD_UNLOCK_SERVER` | 2 | `lock_payload_unlock_server` |
| `UNLOCK_USER_PASS` | 3 | `unlock_user_pass` |

`none` está respaldado por el código de la app; no es un nombre adivinado.
La corrección candidata del modo general es **`main.g.a = "none"`**.
No usar `false`, `"false"` o `"unlocked"` como reemplazos intercambiables.

## Reproducción del análisis nativo

El script `scripts/probe_hc_access_modes.py` requiere el repositorio y el
`libf2c.so` extraído del split ARM64 del APK aportado. Rechaza otra biblioteca
por hash antes de crear la máquina. Dependencias opcionales en
`scripts/requirements-native-probe.txt`; no son dependencias del exportador.

```bash
python -m pip install -r temporary/original-app-config-export/scripts/requirements-native-probe.txt
python temporary/original-app-config-export/scripts/probe_hc_access_modes.py \
  --library /ruta/privada/libf2c.so \
  --output /ruta/privada/nuevo-access-enum.json
```

La sonda completa 1174 inicializadores y la entrada JNI nativa en un entorno
modelado, resuelve las reubicaciones ELF RELATIVE/GLOB_DAT/ABS64 y extrae el
registro real de métodos del enum. Emula referencias, arrays y boxing usados
por esas cuatro etapas, reproduce primitivas de libc sin acceso al SO y detiene
cualquier llamada no soportada. Cada entrada tiene límite de instrucciones.
Los bucles XOR repetidos se aceleran con su transformación exacta; se compara
el bucle ARM64 original con datos sintéticos de 257 bytes antes de extraer.

Se detiene después de las cuatro construcciones: no inicializa el resto de la
app, no ejecuta el parser JSON completo y no sustituye una importación Android.
No se publican APK, bibliotecas, volcados de memoria ni conexiones reales.
Evidencia resumida: `results/access_enum_2026-10-26.json`.

## Nuevas muestras privadas

| Archivo nuevo | Cambio | Estado |
| --- | --- | --- |
| `D_access_none.hc` | Solo `main.g.a: "lock_all" → "none"` | AEAD local correcto; importación/edición pendientes |
| `E_combined_none.hc` | Acceso `"none"` + nota + URL solicitadas | AEAD local correcto; importación/edición pendientes |

Ambos conservan host, puerto, credenciales, payload, `j`, HPR1, sidecars y los
metadatos desconocidos. Ningún otro flag de protección cambia. No desactivan
expiración, contraseña, HWID ni políticas remotas.

El script individual ahora admite únicamente los cuatro strings observados para
cambios de acceso. La excepción booleana sigue disponible **solo para reproducir
el negativo histórico**. La matriz original A–E conserva ese diagnóstico; para
los nuevos candidatos usar el nuevo script:

```bash
python temporary/original-app-config-export/scripts/create_hc_access_followup.py \
  --source /ruta/privada/source_original.hc \
  --output-dir /ruta/privada/hc-access-none-nuevo

python temporary/original-app-config-export/scripts/audit_hc_matrix.py \
  --source /ruta/privada/source_original.hc \
  --historical /ruta/privada/export_rejected.hc \
  --matrix-dir /ruta/privada/hc-access-none-nuevo \
  --output /ruta/privada/hc-access-audit-nuevo.json
```

Hashes de esta generación: `results/access_followup_2026-10-26.json`.
Auditoría de todos sus tags y bytes conservados:
`results/access_followup_audit_2026-10-26.json`.

## Validación y siguiente paso

- 13 pruebas del laboratorio y 9 existentes del codec pasan.
- Las nuevas muestras pasan sus cinco tags AEAD en dos backends, mantienen
  `main.g.a` como string y no cambian restricciones ajenas.
- El fixture sintético de sidecar principal ahora usa su AAD `m:x`; copiar el
  ciphertext de `s0:x` producía un fixture no auténtico que la auditoría más
  estricta detectó. No se modificó ningún motor productivo.
- Importar **D_access_none.hc** en el mismo HTTP Custom y comprobar si acepta el
  archivo y deja editar los campos esperados. Después probar E. Registrar ambos
  resultados por separado: aceptar un archivo no garantiza que todos sus
  controles o políticas remotas queden desactivados.

**Compatibilidad confirmada por el propietario:** baseline, nota y URL de la
matriz original. **Pendiente:** los dos candidatos `none`, su importación y
editabilidad real. No se integra todavía ningún exportador en producción.

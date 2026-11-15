# Fusión de nuevas integraciones en Unity QA — 2026-11-15

Destino revisado: `ci/unity-ads-online-qa`, commit
`bf16b394ded19f3fbc551376187c617560dfca19`.
Origen revisado: `feat/nuevas-integraciones`, commit
`46d7b4ffd67afbd87c76168379d306adbf8782f0` (2026-11-12).
Base común: `8871c13b8e708341d7d2a758cfb102238fec35df`.

## Comparación

Se descargó el historial completo antes de comparar. Git registra 29 commits
exclusivos del origen y 175 del destino. Esto no equivale a 29 funciones nuevas:
9 parches son equivalentes a cambios ya aplicados en el destino, y varias de
las otras funciones también están integradas allí con desarrollo posterior.

La fusión conserva ambos historiales mediante dos padres y mantiene el código
operativo de Unity QA. Se añaden el expediente de investigación de HTTP Custom
build 934, sus herramientas/pruebas, notas de versiones y documentación de las
funciones de anuncios, V2Ray, créditos Telegram y comercio nativo.

## Resolución de los cuatro conflictos

| Archivo | Resolución y motivo |
|---|---|
| `AccountDrawer.kt` | Mantener el destino: perfil/avatar reales, sesión restaurada, notificaciones, actividad, soporte y accesos actuales. La versión del origen es una base anterior y más limitada. |
| `MainActivity.kt` | Mantener el destino: conserva el enlace autorizado de Hex Tunnel además de las restricciones de enlaces existentes. |
| `NativeCommerceScreens.kt` | Mantener el destino: autenticación y catálogo conectados, precios del servidor, seguridad, compras y flujos actuales. El origen contiene una fundación UI anterior con precios referenciales y acciones deshabilitadas; no sustituye la implementación posterior. |
| `SpDecodeApp.kt` | Mantener el destino: aviso/postergación del catálogo y callback de enlaces externos para la categoría SSH, sin retirar los cambios ya presentes de V2Ray/Telegram. |

Los cambios entrantes de alias Telegram, normalización de JSON HC, copia de
enlaces V2Ray, idioma y navegación ya están presentes en el destino. Las
comprobaciones de contrato Android confirman que permanecen.

## Documentos históricos y alcance de HTTP Custom

Los documentos de 2026-11-11/12 incorporados describen el estado de esas fechas.
En particular, `docs/android/NATIVE_COMMERCE_STORE_ACCOUNT_AUTH_2026_11_12.md`
es la fundación histórica de UI: sus menciones de cuenta/pagos sin conectar no
invalidan el desarrollo posterior que ya contiene Unity QA. No usar ese texto
para volver a pantallas de demostración o deshabilitar los flujos actuales.

El expediente `analysis/xyz.easypro.httpcustom/934` conserva estado `PENDING`:
sus diagnósticos no prueban descifrado completo de los nuevos payloads. Esta
fusión no habilita métodos adicionales ni modifica el descifrador operativo.

## Verificación

- 34 pruebas de `tests.test_android_unity_release_contract`: correctas.
- 29 regresiones HTTP Custom (`test_http_custom_899`, `test_hc_sip_new_variants`,
  `test_cloud_c2_hc`, `test_hc_legacy57`): correctas.
- 3 pruebas offline/sintéticas del expediente HC 934: correctas.
- Auditoría F7-A0 con `--enforce` sobre todos los archivos entrantes: sin
  hallazgos bloqueantes (el auditor es parcial, no certifica compatibilidad real).
- Árboles Git de `android`, `android-admin`, `cloud` y `.github` idénticos al
  destino previo a la fusión. Se conservan los iconos y tokens del parche de
  20 apps, las correcciones de persistencia de recursos y los workflows.
- No se eliminan archivos existentes; las modificaciones de README son
  exclusivamente aditivas. Los documentos y el expediente importados conservan
  sus bytes de origen salvo las adiciones conciliadas en los README.

El resultado no requiere cambios de código Android ni una nueva compilación
para resolver esta fusión. No se compiló una APK ni se desplegó la VPS en esta
sesión. Los resultados anteriores no equivalen a una nueva validación física
en un teléfono ni a una ejecución completa de todos los workflows de GitHub.

# Integración de Unity QA en main — 2026-11-15

Destino previo: `main`, `8be08b5b898c539c4288542fc35aa07bd0db85b8`.
Origen revisado: `ci/unity-ads-online-qa`,
`26f07ec40a87a5f0f11f3c050f0ad13250eb2600`.
Base común: `45db1d4ed4c18df6911a7f77a744776353223a8c`.

## Conservación de ambas ramas

Git registra 2 commits exclusivos de main y 763 del origen. La fusión de tres
vías no produce conflictos y conserva ambos historiales mediante dos padres.

Los dos commits exclusivos de main afectan únicamente a
`.github/workflows/owner-recover-signing-keystore.yml`. Ese archivo se conserva
byte por byte: ejecución manual, repositorio/propietario/rama autorizados,
confirmación explícita, permisos de lectura y artefacto cifrado de un día.
No se ejecutó ese workflow ni se accedió a secretos de firma.

Los árboles de `android`, `android-admin`, `cloud`, `decoders`, `scripts` y
`tests` se conservan exactamente como en Unity QA. Incluyen el parche de
20 apps, iconos, configuración de tokens FMT/RH, sesiones/interfaz existentes
y la persistencia del override de recursos de la VPS.

La antigua prueba del visor ubicada en `src/androidTest` es reemplazada por
la suite ya existente de Unity QA en `src/sharedAndroidTest`, adaptada al visor
continuo y al motor de resultados grandes. No se reintroduce la clase antigua
duplicada ni el comportamiento anterior de expansión manual.

## Corrección documental necesaria para la auditoría

La primera auditoría F7-A0 del cambio completo detectó 20 manifiestos cuyo
campo `dependencies` era un objeto con una referencia al lockfile, cuando el
esquema exige una lista. En 6 casos también había rutas comentadas o referencias
a directorios temporales dentro de `code_paths`.

Se normalizan exclusivamente esos metadatos:

- `dependencies` contiene las entradas exactas del lockfile existente.
- El objeto de referencia original se conserva en `dependencies_reference`.
- `code_paths` contiene archivos existentes del repositorio. Para Royal y
  UT Loop se enlazan sus adaptadores reales, porque los nombres de scripts
  externos citados en el expediente no estaban incorporados con esos nombres.
- Las referencias históricas originales se conservan en `code_paths_reference`
  cuando se normalizan.
- Permanecen iguales los lockfiles, versiones, estados, limitaciones, objetivos,
  scripts y resultados de investigación. Los valores UNKNOWN y NEEDS_REVIEW
  no se convierten en afirmaciones verificadas.

Esto corrige el formato exigido por el auditor; no habilita nuevas rutas ni
certifica métodos pendientes. La auditoría es estructural y parcial.

## Comprobaciones

- F7-A0 `--enforce` sobre todo el cambio hacia main: sin bloqueos tras la
  normalización; 103 expedientes estructuralmente completos.
- 151 pruebas offline/sintéticas de los 20 expedientes: correctas.
- 71 pruebas del instalador y herramientas de VPS: correctas.
- 41 pruebas de contrato Android y guardas HPKE: correctas.
- Suite web completa: 770 correctas, 4 fallos previos y 3 omitidas (777 casos); los mismos cuatro fallos se habían reproducido en la base anterior, sin nuevos fallos en esta suite.
- Workflow de recuperación de firma: contenido idéntico al main anterior,
  condiciones manuales preservadas y sintaxis Bash válida.
- Ningún archivo de configuración de producción ni secreto real fue leído
  para estas verificaciones. La fusión no despliega la VPS ni publica APK.

Las cuatro pruebas web que ya fallaban antes de esta fusión permanecen como
pendientes conocidos: navegación del panel, documentación del permiso
biométrico y dos expectativas de condiciones de tienda. No equivalen a
conflictos de Git ni se declaran corregidas en esta integración.

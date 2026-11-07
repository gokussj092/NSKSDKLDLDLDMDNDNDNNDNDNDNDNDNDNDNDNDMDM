# F7-A0-P06 — Cobertura del gate, dependencias y legado

**Rama:** `feat/nuevas-integraciones`  
**Estado:** PARCIAL / VALIDACIÓN CI; sin despliegue en producción.  
**Ámbito:** inventario estático y análisis de impacto, NO ejecución automática de APK o herramientas.

## Objetivo y antecedentes

Extender el gate parcial de P01–P05 a fuentes históricas de `decoders/Python/`, proveedores `apps/`, `cloud/workers/python/` (incluido `exports/`), `cloud/web/lib/`, rutas seleccionadas de `cloud/web/app/api/` y scripts compartidos de `scripts/apk_analysis/`. La protección previa de cambios y expedientes sigue operando en `scripts/ci/check_method_evidence.py`.

No modificar ni copiar/reescribir las **63 herramientas** originales usadas por Work. Preservar que `F7-A0-P05` está **PARCIAL**, y que el entorno de análisis Android→Cloud aún no existe para usuarios. Un hash o referencia textual no acredita que un método funcione.

## Implementado en esta subfase

- `scripts/ci/check_a0_p06_coverage.py`: escaneo read-only con biblioteca estándar, sin importar métodos ni abrir archivos APK. Descubre fuentes dinámicamente y produce SHA-256 de sus **bytes de código**, más referencias estáticas de importación y etiquetas de incertidumbre de rutas dinámicas. No se generan archivos de historial por versión Android.
- Grafo inverso de dependencias estáticas: al modificar una fuente, informa los módulos afectados por imports directos/transitivos y los dossiers `analysis/<package>/<build>/` que la referencian en `MANIFEST.json.code_paths`.
- En el gate de PR, un cambio a una fuente de método requiere un expediente enlazado **actualizado en la misma PR**; los expedientes enlazados a consumidores alcanzados también se solicitan para revisión. Rutas/plugins dinámicos no resueltos quedan marcados como `UNKNOWN`: sin fingir cobertura total.
- `analysis/platform/apk-tooling/legacy_provider_baseline.v1.json`: los **78 directorios de proveedores** presentes en la línea base `4fddee8924e58a9d1e6476974e9b7a9adda3e495` quedan registrados individualmente como `LEGACY_UNREVIEWED`. Este listado cubre nombres de directorio, NO hashes de todos los métodos ni aprobaciones.
- `tests/test_a0_p06_coverage.py`: fixtures deterministas para cambios con/sin expediente, impactos indirectos Python/JS, rutas de API, imports dinámicos, exclusión de documentación y detección de nuevos proveedores.
- `.github/workflows/f7-a0-method-evidence.yml`: ejecuta la suite P06, genera `f7-a0-p06-coverage.json` en cada push/PR y evalúa cambios contra SHA base del PR con `--enforce`.

### Política de legado y excepciones

Las fuentes heredadas **no modificadas** generan inventario/backlog y no rompen CI por falta de dossier histórico. Cuando se modifica un método heredado, la falta de un expediente actualizado **bloquea** el cambio: no existe un bypass automático para nombres incluidos en la baseline.

Las modificaciones únicamente documentales/de pruebas o fuera del alcance del método no necesitan expediente de método. Cualquier excepción adicional que afecte métodos requerirá una justificación y autorización humana específica con rutas/consumidores afectados y expiración; el registro inicial contiene `exceptions: []`. No se ha implementado ningún permiso automático basado en excepciones.

### Comandos reproducibles

```bash
python -m unittest discover -s tests -p 'test_a0_p06_coverage.py' -v
python scripts/ci/check_a0_p06_coverage.py --output /tmp/f7-a0-p06-coverage.json

# Comparar con el SHA de la base real en un checkout completo:
python scripts/ci/check_a0_p06_coverage.py --enforce \
  --base-ref "<SHA_BASE_DEL_PR>" --output /tmp/f7-a0-p06-gate.json
```

La auditoría produce metadatos de rutas, hashes y consumidores, nunca contenido del código, secretos, APK, descompilaciones ni informes sensibles. Las referencias estáticas, los hashes y las importaciones no constituyen aprobación de ejecución ni equivalen a pruebas de catálogo VPN real.

## Matriz de validación

| Comprobación | Alcance |
| --- | --- |
| Escaneo de decoders/Cloud/workers/plugins | Estático por ruta, extensión y sintaxis |
| Integridad de las 63 herramientas | Gate previo P01/P02, preservado |
| SHA-256 de fuentes y dependencias | Auditoría dinámica en JSON sanitizado |
| Gate para modificación de métodos | Solo PR; requiere dossier actualizado |
| Dependencias indirectas | AST Python e imports JS literales, no análisis dinámico completo |
| Proveedores heredados | 78 carpetas marcadas como `LEGACY_UNREVIEWED` |
| Pruebas de VPN externas / Android E2E | NO realizadas en P06 |
| Check requerido en protección de rama | NO configurado ni certificado aquí |

## Pendientes para cerrar P06/A0

1. Confirmar CI del último commit y registrar las ejecuciones en este documento.
2. Revisar manualmente posibles falsos positivos/negativos del grafo: importaciones dinámicas y registros de plugins, caminos indirectos del worker y `cloud/web/app/api/` no detectados.
3. Asociar a cada consumidor real las dependencias **directas y transitivas instaladas** con distribución, licencia, versión y hash verificable. Los SHA-256 del código fuente no sustituyen los lockfiles ni la revisión jurídica de P01.
4. Migrar gradualmente los proveedores heredados sin expediente actualizado, y exigir dossiers al **primer cambio futuro**.
5. Validar gate de PR contra una PR de prueba sin permiso de merge y revisar reglas reales de protección de rama (P07).
6. Mantener sin activar A4/A5/A9 y el análisis automático hasta completar autorización, seguridad, privacidad, persistencia y pruebas end-to-end.

**Resultado de P06:** implementación parcial. No marcar DONE, ni F7-A0 cerrada, ni servicio APK al 100 % por aprobar tests sintéticos.

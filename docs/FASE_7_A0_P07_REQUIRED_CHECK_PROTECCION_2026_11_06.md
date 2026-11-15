# F7-A0-P07 — Check obligatorio y protección efectiva de rama

**Rama de trabajo:** `feat/nuevas-integraciones`. **Estado:** controles CI IMPLEMENTADOS Y VALIDADOS, protección remota NO activada por decisión expresa del propietario (opcional y aplazada). No hacer merge a `main` ni desplegar producción.

## Decisión posterior del propietario — sin Branch Protection

El propietario de SP-DECODE confirmó que revisa manualmente las ejecuciones de GitHub Actions antes de cualquier fusión o despliegue y **no desea activar Branch Protection por ahora**. Se mantiene el auditor CI P07 y las pruebas de wiring; **no** se considera obligatoria la regla remota para avanzar a P08/P09. La implementación queda anotada como `OPCIONAL_APLAZADA`, no se atribuye a GitHub un bloqueo de merge inexistente. La validación del código y los métodos sigue siendo obligatoria.

Los pasos de activación siguientes se conservan únicamente como referencia futura **si el propietario decide habilitarla**, no como instrucciones pendientes de ejecución automática.

## 1. Hallazgo de configuración real

Consulta autenticada de solo lectura al repositorio (7 de noviembre de 2026 UTC):

- `GET /repos/gokussj092/NSKSDKLDLDMDNDNDNNDNDNDNDNDNDNDNDNDMDM/branches/main`: `protected: false`, `protection.enabled: false`, `required_status_checks.contexts: []`.
- La misma consulta a `feat/nuevas-integraciones`: `protected: false`; no tiene required checks.
- `GET /repos/.../rulesets`: lista vacía `[]`.
- `GET /repos/.../branches/main/protection`: **403 Resource not accessible by integration**. La integración GitHub conectada permite consulta/cambios de código, pero **no permite activar o modificar protección** mediante ninguna de sus acciones disponibles.

**Conclusión:** que el workflow aparezca SUCCESS NO implica que GitHub bloquee un merge. La regla de protección **no fue creada**. No afirmar que P07 está cerrada.

## 2. Gate listo para ser requerido

Usar los checks nativos que ya aparecen en la PR #110:

| GitHub Actions | Job/contexto esperado | Objetivo |
| --- | --- | --- |
| F7-A0 Method Evidence | `evidence-gate` | Inventario/ABI/licencias pendientes, P01–P06, SHA y expediente obligatorio |
| Validate SP-DECODE | `validate` | Suite general Cloud/servidor y contratos |

`.github/workflows/f7-a0-method-evidence.yml` ejecuta el job `evidence-gate` en **todas las pull requests hacia main** (sin filtros de paths), con `permissions: contents: read`. El paso P06 recibe el SHA de la base, el SHA real del head y el cutover `4fddee8924e58a9d1e6476974e9b7a9adda3e495`.

La política `analysis/platform/apk-tooling/p07_required_checks.v1.json` contiene los identificadores esperados. El auditor `scripts/ci/check_a0_p07_required_check.py` verifica en modo offline que el workflow conserva el evento PR a `main`, nombre estable, job no omitido, sin ignorar fallos, y sigue ejecutando ambos gates y las pruebas de P06/P07. **No consulta ni modifica GitHub.**

## 3. Activación pendiente en GitHub (requiere cuenta con permisos de administración)

Entrar en el repositorio > **Settings > Branches** (o **Settings > Rules > Rulesets**, según la interfaz) > crear regla para `main`. Configurar:

1. **Require a pull request before merging** y **Require status checks to pass before merging**.
2. Seleccionar los checks existentes de GitHub Actions `evidence-gate` y `validate` (confirmar su contexto efectivo en el selector; evitar nombres genéricos duplicados de otros workflows).
3. **Require branches to be up to date before merging** (`strict`) y prohibir force-push y borrado de `main`.
4. No configurar bypass implícito: revisar administradores y excepciones de acuerdo con la política del repositorio.
5. Guardar la regla y **volver a leer** la rama por API o interfaz. Debe aparecer `protected: true` y los checks obligatorios activos. Conservar evidencia de este resultado sin secretos.

La configuración de revisión humana (por ejemplo, número de aprobaciones o CODEOWNERS) debe decidirse según los colaboradores disponibles; esta subfase no impone de forma inesperada un requisito que impida trabajar al propietario.

**No pegar tokens, claves de GitHub ni contraseñas en el repositorio o los logs.**

## 4. Pruebas obligatorias para cierre

- Positiva: PR #110 debe completar `evidence-gate` y `validate` en verde después de la corrección P06 y después de cada actualización del workflow.
- Negativas locales: `tests/test_a0_p06_coverage.py` modifica un método *después* del cutover y demuestra que falta de expediente produce `FAIL`. Verifica que el código heredado previo se **informa** y no se aprueba retroactivamente.
- Negativas del workflow: `tests/test_a0_p07_required_checks.py` comprueba que pérdida del trigger main, cambio de nombre, path filters, job condicionado, error ignorado, omisión del gate y alteración del cutover bloquean el contrato.
- **Negativa GitHub real:** después de activar branch protection, validar en una PR controlada sin autorización de merge que un método nuevo sin expediente hace fallar `evidence-gate` y deja el merge bloqueado. No se realizó esa PR ni se creó rama nueva.
- Verificación remota: volver a consultar la configuración requerida en GitHub y registrar fecha, fuente y resultado verificado.

## 5. Comandos de comprobación (sin permisos elevados)

```bash
python -m unittest discover -s tests -p 'test_a0_p06_coverage.py' -v
python -m unittest discover -s tests -p 'test_a0_p07_required_checks.py' -v
python scripts/ci/check_a0_p07_required_check.py --output /tmp/f7-a0-p07-contract.json
```

Para inspección con una sesión `gh` autorizada, sin imprimir credenciales:

```bash
gh api repos/gokussj092/NSKSDKLDLDMDNDNDNNDNDNDNDNDNDNDNDNDNDNDMDM/branches/main \
  --jq '{protected, checks: .protection.required_status_checks}'
gh api repos/gokussj092/NSKSDKLDLDMDNDNDNNDNDNDNDNDNDNDNDNDNDNDMDM/rulesets
```

**Pruebas específicas:** [F7-A0 Method Evidence, PR 42335831332](https://github.com/gokussj092/NSKSDKLDLDMDNDNDNNDNDNDNDNDNDNDNDNDNDMDM/actions/runs/42335831332) **SUCCESS**, 17 pruebas de P06 incluidas y 63 herramientas intactas (commit 4e9093c7); [Push 42335826786](https://github.com/gokussj092/NSKSDKLDLDMDNDNDNNDNDNDNDNDNDNDNDNDMDM/actions/runs/42335826786) **SUCCESS**.

**P07 permanece PARCIAL** hasta que la regla requerida se active y se compruebe el bloqueo real de merge. El éxito del auditor offline es evidencia de wiring, no de protección remota.

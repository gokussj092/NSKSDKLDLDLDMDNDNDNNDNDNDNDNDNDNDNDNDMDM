## Resumen y alcance
- ¿Qué se cambió? ¿Es documentación, UI, método nuevo, corrección de método, catálogo o infraestructura?
- ¿Qué builds y formatos quedan afectados? ¿Hay cambios de seguridad, secretos, Play Console, AAB o VPS?

## Checklist obligatorio para nuevos métodos y revisiones de decodificadores
- [ ] Confirmé si cambia o añade un método VPN (archivo, texto, catálogo, exportación). Si no, justifico que no aplica.
- [ ] Incluí un expediente por versión en `analysis/<package>/<build>/` conforme a [política obligatoria](../analysis/METHOD_EVIDENCE_POLICY.md).
- [ ] Incluí MANIFEST.json, ANALYSIS.md, REPRODUCE.md y RESULTS.md.
- [ ] Guardé los scripts PROPIOS de investigación realmente usados en tools/ y documenté las herramientas compartidas/terceros con versiones y comandos exactos.
- [ ] Incluí pruebas positivas y negativas apropiadas y evidencias reales; los mocks se identifican como sintéticos.
- [ ] Enlacé la ruta del expediente desde la ficha del decodificador y documenté compatibilidad heredada.
- [ ] No subí secretos, APK originales sin permisos, usuarios, datos descifrados sensibles ni respuestas autenticadas privadas.
- [ ] El método está correctamente etiquetado VERIFIED / PARTIAL / PENDING / FAILED / MAINTENANCE; un método sin pruebas reales no se anuncia como verificado.

## QA y autorización
- [ ] Ejecuté los tests relevantes o documenté exactamente qué no pude probar.
- [ ] No activé pagos, IA, Play In-App Updates, descifrado Cloud, ni despliegues sin permiso del propietario.
- [ ] No hice merge a main ni despliegue automático fuera del alcance autorizado.

**Importante:** el gate automático de analysis/ está pendiente. La revisión humana de esta checklist es obligatoria mientras tanto. El cumplimiento no se infiere únicamente por marcar casillas.

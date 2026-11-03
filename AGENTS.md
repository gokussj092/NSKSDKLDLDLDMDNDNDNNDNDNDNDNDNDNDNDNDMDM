# Instrucciones obligatorias para asistentes y colaboradores — SP-DECODE

**Regla prioritaria desde 2026-11-02:** ningún nuevo método de una aplicación VPN, actualización de método o nueva compatibilidad de archivos/texto/catálogos/exportaciones se considera terminado sin **un expediente en analysis/** que conserve TODOS los scripts propios usados durante la investigación, herramientas/recetas, pruebas, evidencia verificable, versiones y limitaciones.

Lea y cumpla [analysis/METHOD_EVIDENCE_POLICY.md](analysis/METHOD_EVIDENCE_POLICY.md) antes de investigar, modificar o habilitar cualquier proveedor. Los documentos previos en decoders/Python/apps/ANALYSIS.md y scripts/apk_analysis/RESTORE.md no sustituyen el expediente. Conserve compatibilidad con scripts existentes; no borre scripts de investigación.

**Al trabajar en cada método:**
1. Verifique packageName/versionCode, fuente autorizada y hashes, y abra analysis/<package>/<build>/.
2. Almacene scripts propios reales en tools/, comandos en REPRODUCE.md, MANIFEST.json, ANALYSIS.md, RESULTS.md y tests reproducibles con fixtures sanitizados.
3. Distinga claramente lo observado, lo sintético, lo realmente verificado y lo pendiente; no afirme descifrado remoto ni catálogo funcional sin prueba real.
4. No suba secretos, credenciales, APK de terceros sin permisos, datos de usuarios, ni configuraciones VPN sensibles a Git.
5. No declare DONE/VERIFIED ni active catálogo si el expediente o la validación faltan. Documente PENDING/FAILED cuando sea el caso.
6. Cualquier propuesta de script generado mediante IA se prueba de manera aislada y exige revisión humana antes de entrar en producción.

**Bloqueo CI:** está ESPECIFICADO pero NO IMPLEMENTADO. No afirmar que un job ya impide merges por incumplimiento; la revisión humana de este requisito es obligatoria mientras se crea el validador.

**Planes pendientes que NO autorizan implementación:** [Google Play Flexible/Inmediata](docs/android/PLAY_IN_APP_UPDATES_PENDING_2026_11_02.md) y [fase 7 APK: dos salidas, informe o código con IA](docs/FASE_7_APK_AUTOANALISIS_DOS_SALIDAS_PENDING_2026_11_02.md). No activar Play publishing, cuentas de servicio, API keys, pagos, importación de APK ni código generado automáticamente sin autorización posterior. Mantener firma, versión y seguridad existentes.

**Vistas previas solicitadas por el propietario:** cuando se pida una vista previa de UI, mostrar de preferencia componentes visuales interactivos directamente en el chat, no una imagen generada ni texto plano a menos que el usuario lo pida explícitamente.

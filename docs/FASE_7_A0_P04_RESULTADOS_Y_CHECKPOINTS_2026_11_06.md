# F7-A0-P04 — Contratos de checkpoint, resultado y progreso seguro

**Rama:** feat/nuevas-integraciones. **Estado:** implementación de contratos y pruebas sintéticas; sin habilitación de análisis APK remoto.

## Objetivo

Conservar los avances que genere el futuro analizador automático de APK y evitar repetir todo el análisis ante fallas. P04 se conecta lógicamente a P03 (espacios temporales independientes y caché persistente) sin modificar ni ejecutar los 63 scripts que Work ya ha utilizado.

**P04 no es aún el servicio de análisis APK:** las fases A1–A5/A9 deben implementar subida/autenticación, almacenamiento cifrado, cola, orquestador, selección aprobada de herramientas y comunicación Android.

## Archivos y responsabilidad

| Archivo | Contrato |
|---|---|
| cloud/apk_analysis/checkpoint_journal.py | Diario de eventos append-only con SHA-256 enlazados; permisos privados, bloqueo de escrituras concurrentes, reemplazo atómico/fsync, replay y recuperación |
| analysis/platform/apk-tooling/schemas/checkpoint-event.v1.json | Esquema estable de un checkpoint individual y sus niveles de evidencia |
| analysis/platform/apk-tooling/schemas/result-event.v1.json | Resultado final persistido, con recibo que corresponde exactamente al último checkpoint REPORT exitoso |
| analysis/platform/apk-tooling/schemas/user-progress.v1.json | Resumen de progreso limitado: no incluye rutas, hashes, referencias internas, contenido de archivos ni credenciales |
| tests/test_a0_checkpoint_contract.py | Pruebas de corruptelas, crash/interrupción, idempotencia, privacidad, secuencia y separación de limpieza |
| tests/test_a0_checkpoint_schemas.py | Verifica coherencia entre tipos/enums de schemas y validador actual |

El **1** de los esquemas indica versión de **protocolo**, no versión de la aplicación Android. No hay que crear un registro por cada build APK.

## Estados y evidencia

- Etapas: UPLOAD_VALIDATED, STATIC_INVENTORY, RESOURCES, DEX, ELF, METHOD_REVIEW y REPORT. Una etapa fallida o parcial no destruye registros previos. No se permite retroceder de etapa.
- Estados: OK, PARTIAL, FAILED, NEEDS_HUMAN. Los fallos y escalados requieren códigos de error cerrados y nunca texto arbitrario con datos del APK.
- Evidencia: UNKNOWN, OBSERVED, INFERRED, VERIFIED_SYNTHETIC y VERIFIED_REAL. El último exige referencias a autorización e inspección independiente; **esas referencias son identificadores, no prueban por sí solas la firma/validez del documento**. El servicio A5 tendrá que validarlas antes de publicarlas.
- Privacidad: USER_PRIVATE y ADMIN_RESTRICTED. El progreso para Android contiene únicamente estados y el indicador de salida disponible. El backend A1/A4/A5 deberá aplicar autenticación, propiedad del trabajo y control de acceso por usuario.
- Cada artefacto se representa mediante obj:uuid, SHA-256 y longitud, pero **los bytes no se almacenan en el diario**. Deben estar cifrados, accesibles por permiso y verificados en almacenamiento duradero independiente.

## Publicación final, idempotencia y limpieza

1. El orquestador autorizado agrega checkpoints al diario host-only; cada evento tiene número continuo, hash del evento anterior y su propio hash de contenido.
2. Un reinicio puede reconstruir la secuencia desde discos privados y detectar diferencias, truncado o huecos. Una escritura incompleta que dejó un fichero temporal oculto no se toma como avance confirmado.
3. Para publicar un resultado final, debe existir un checkpoint REPORT exitoso. El proceso confiable llama a finalize_result con un **verificador externo del objeto**, que debe confirmar existencia durable, hash, longitud y permisos/propiedad del trabajo.
4. Solo después se escribe RESULT_COMMITTED de forma atómica e idempotente. Para recuperación, cleanup_receipt facilita al host el digest/referencia; el sistema A5 tendrá que comprobar otra vez la existencia e identidad del resultado antes de llamar a WorkspaceStore.result_persisted de P03.
5. P03 **solo borra** input/scratch/output-staging del trabajo tras ese recibo o un cierre terminal explícito. Los recursos persistentes (JADX y dependencias) sobreviven. Un escalado a soporte humano no se limpia prematuramente.

**Advertencia técnica:** la cadena SHA-256 es un mecanismo de detección de corrupción, **no** una firma digital ni defensa ante un administrador malicioso con escritura. Se requiere firma/HMAC/KMS, almacenamiento cifrado, aislamiento de tenants, control de acceso y respaldos recuperables antes de producción. El journal está diseñado para **un host**, con fcntl.flock; una orquestación distribuida necesitará almacenamiento transaccional y locking de base de datos.

## Pruebas y comandos

```bash
python -m unittest discover -s tests -p 'test_a0_checkpoint_contract.py' -v
python -m unittest discover -s tests -p 'test_a0_checkpoint_schemas.py' -v
```

Las pruebas utilizan IDs sintéticos y no descargan ni analizan APK, no llaman Frida/ADB/JADX y no dependen de las herramientas actuales. Se agregaron al workflow F7-A0 sin cambiar los flujos de publicación ni los workflows Cloud.

## Pendientes de integración para cerrar P04

- A4/A5: backend cifrado de objetos, verificador externo real de SHA-256/longitud/tenant y escritura de recibos con transacción de BD; retry y crash recovery bajo máquina real.
- A5: afirmar VERIFIED_REAL solo cuando el verificador independiente confirme evidencia/autorización, no con tokens inventados.
- A5/A6: cierre final sin resultado, retención de casos humanos, reanudación de etapas y limpieza por cuotas/TTL sin borrar pendientes.
- A9: exponer únicamente el esquema de progreso seguro al cliente Android ya autenticado; falta API, autenticación/consentimiento y actualización de interfaz.
- P05/P08: ejecutar corpus APK/APKS autorizado, inyección de fallos, carga de disco, carreras de procesos, contenedores Linux y pruebas E2E con servidor real.

**No declarar la función APK comercial lista hasta superar las pruebas reales de A4/A5/A9.**

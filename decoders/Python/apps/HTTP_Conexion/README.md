# HTTP Conexión 1.2.9 / build129

El script de catálogo incluye la consulta automática de `ockla_url` y `gretta_pass` en Firebase. Sin argumentos, obtiene la pareja vigente, descarga el catálogo con el protocolo original y lo descifra íntegramente. No requiere un probe externo, tokens manuales ni editar la contraseña en cada cambio.

Pareja en caché durante una hora; un fallo de descarga/descifrado fuerza una consulta nueva y un único reintento. Firebase ausente, parámetros inválidos o destino no aprobado producen error, sin volver al default/asset antiguo. Solo HTTPS raw.githubusercontent.com, sin redirecciones ni URLs aportadas por el cliente. Las opciones públicas Firebase del APK están en el backend; los tokens emitidos solo viven temporalmente en memoria y se intenta eliminar la instalación al terminar.

La contraseña de la capa exterior se pasa por operación al worker aislado; no cambia globals ni la clave GCM interna. Archivo y --stdin conservan compatibilidad con entradas históricas y con el sobre interno versionado. La salida pública sigue siendo el JSON completo con nombres, metadata y todos los campos GCM autenticados. El CBC exterior no autentica la metadata.

Verificación real actual: catálogo107, 244 servidores, 5.325 campos GCM, documento entero igual a JCA/CLI/worker. Rotación de contraseña probada con un fixture JCA ficticio y worker real. Node con red simulada pasa; transporte Node real en VPS y despliegue pendientes. Sin cambios ni build Android, sin exportación unlocked certificada.

[Expediente](../../../../analysis/com.doriaxvpn.unlimited/129/ANALYSIS.md) · [Actualización automática y receta](../../../../analysis/com.doriaxvpn.unlimited/129/REFRESH_2026_11_04.md).

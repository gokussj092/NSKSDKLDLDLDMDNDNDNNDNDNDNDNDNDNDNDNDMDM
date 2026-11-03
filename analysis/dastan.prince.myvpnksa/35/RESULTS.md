# Resultados y límites

## VERIFIED_REAL

| Entrada | Versión | Servidores | Payloads | Verificación |
| --- | --- | --- | --- | --- |
| assets/gremlin.json |49.9|22|1025|JSON entero igual a Java, CLI y child worker|
| Updater original público |82.0|28|1193|HTTP200 real; JSON entero igual a Java, CLI y child worker|
| Segunda descarga por adaptador operativo |82.0|28|1193|Mismo SHA256, comparación completa repetida|

Respuesta remota613664bytes, SHA256
`cb3a9c0eb85332343b0c256622853e50bc93b1913c122ce37881385b1a628c0d`.
Sin cookies, autenticación, cuentas ni atestación. Las listas Premium/Vip/Private
estaban vacías. El descifrado comprende el sobre completo; los registros ya
son texto y se conservan sin XOR. No se inventaron servidores ni payloads.

## VERIFIED_SYNTHETIC y regresión

11 pruebas Python: vector ficticio/Java, stdin/CLI, child worker, conservación
de texto hexadecimal y Unicode, campos desconocidos, duplicados, NaN, esquema,
vacíos, HTML, truncado/corrupción, límite8MiB, petición fija y fallo de red.
La referencia Java del vector es independiente del encoder Python de pruebas.

135 pruebas Node en15 archivos: nuevo proveedor y regresiones de catálogo,
iconos, disponibilidad, controles persistentes, TLS/DNS, redirecciones, URL
arbitraria y contrato entero no parcial. Los tests del nuevo proveedor simulan
HTTP; los catálogos/iconos generales también se probaron con los originales
del repositorio materializados desde el commit base, sin cambiar esos archivos.
Node se ejecuta desde `cloud/web`, su cwd previsto.

Los conteos/comandos/estado de ejecución real se conservan en
`generated/checks.json`; fixtures ficticios y hashes en MANIFEST. Los fixtures
no prueban conectividad remota; esa evidencia es el GET real separado.

## Intentos fallidos conservados

- Primer candidato con XOR interior de BD NET: `Invalid JNI leading byte`
  en un campo ya texto del remoto. Script original en `tools/history/`;
  corregido al cotejar ruta de lectura de la APK y Java de sobre externo.
- JADX terminó3 con18/9 errores. No se ejecutó Android ni se declaró reconstruida
  toda la app; se contrastó el método de catálogo de manera independiente.
- Primer intento de regresión amplia:30/40; faltaban fixtures/rutas del checkout
  parcial y se usó cwd raíz. Segundo:50/52, quedaba un módulo compartido ausente.
  Se materializaron sin modificar los originales del commit base, se corrigió
  cwd y pasó la ejecución final. La lista histórica de providers esperados se
  actualizó para incluir FNF y las dos incorporaciones previas.
- Node real: salida3, `NETWORK_UNAVAILABLE/REMOTE_NETWORK_DENIED` antes de
  transporte. No se retiraron ni sortearon controles de red.

## PENDING / alcance de entrega

Replay Node de ciphertext real y respuesta real del worker:
`SIMULATED_HTTP_REAL_BYTES`, documento entero aprobado. **No es HTTP real Node**.
Falta probar ese transporte en el VPS y efectuar su rollout por el operador.

Código preparado en rama de trabajo: proveedor `fnf-tunnel-bd`, icono original
500×500/52532bytes, ficha, switch, motor offline y validación completa. Piso de
catálogo65/61 fichas; un valor VPS mayor conserva monotonía.256 formatos sin
incorporar formatos de archivo/texto/exportación para esta app.

No se modificó ni compiló Android, no se esperaron workflows Android, no se
fusionó main y no se desplegó VPS. No se probaron conexiones VPN ni vigencia de
cuentas; no se certificó firma Play/latest ni integridad autenticada de XXTEA.
JSON real y APK permanecen fuera de Git. Revisión automática de licencias y
aprobación Fase7 siguen pendientes, al igual que el validador CI de evidencia.

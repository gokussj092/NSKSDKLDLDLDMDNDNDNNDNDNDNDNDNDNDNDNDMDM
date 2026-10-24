# BD NET build 111 — validación

## Comprobaciones reales

| Documento | Versión | Free_servers | Payloads | Campos distintos | Anexo binario |
|---|---|---|---|---|---|
| Asset del APKS | 57 | 20 | 257 | 187 | 1 ubicación |
| GET literal | 56 | 19 | 255 | 187 | 1 ubicación |

Los dos JSON completos coinciden con el oracle Java de XXTEA y readUTF,
incluidos todos los campos internos y el anexo con bytes originales. Los
workers aislados entregan los mismos objetos completos, `isPartial=false`.
Se verificó la descarga real con la CLI, guardado 0600 y comparación completa.
El remoto es anterior al asset; ambos se mantienen separados.

Cinco vectores sobre `xorWithKey` ARM64 original coinciden exactamente.
El emulador está fijado por hash del SO y modela únicamente las operaciones
de cadena C++ requeridas; no ejecuta JNI, firmas, identidad o arranque Android.

```sh
PYTHONPATH=cloud/workers/python:. python -m unittest tests.test_bd_net_vpn -v
python scripts/apk_analysis/bd_net_verify.py /privado/gunny.json /privado/remoto.enc --worker
python scripts/apk_analysis/bd_net_verify.py --file /privado/perfil.bdnet --worker
python scripts/apk_analysis/bd_net_native_oracle.py /privado/libputils.so
```

El runtime usa solo stdlib. El oracle independiente requiere el launcher de
fuentes Java 17+, sin necesitar un ejecutable javac separado; incorpora la
clase de referencia XXTEA ya conservada en apna_oracle.java. Los vectores
readUTF están limitados a 65535 bytes por string; ese límite del oracle no
reduce el límite de 8 MiB del lector. El oracle ARM64 requiere Unicorn y
pyelftools únicamente para análisis.

## Pruebas automatizadas

10 específicas BD NET: catálogo entero, campos internos, binario recuperable,
archivos/enlaces, contraseña y flags conservados, JNI no canónico/NUL/Unicode,
errores y límites, JSON duplicado/no finito, colisiones, API worker, bot,
JSON histórico, CLI stdlib fuera del repo, salida 0600 sin sobrescritura y
referencia Java independiente. El resumen no expone credenciales.

**71 Python aprobadas**: 68 de BD/APNA/Aura/C8/texto/TRV/4U y 3 de paridad
inmutable E (31 vectores originales, 27 sufijos). **295 Node aprobadas** en
toda la web: API autenticada, esquema y consistencia de resultados, icono,
metadatos y switches persistentes. Build web correcto.

Pendientes: exportación `.bdnet` real del build 111, Android/Termux real y
recuperación completa del DEX protegido. La última no es requisito del lector
de formato ya verificado. Sin APK nueva, fusión o despliegue VPS.

# Verificación MTM

Resultado local 2026-10-25: **42 Python / 315 Node aprobadas**, build web
correcto. Incluye MTM, MNR, HTTP Door, worker C8, C0/Android y comparación
byte por byte de los 60 casos C2 con Python/Node/PHP. Los dos desajustes
históricos de httptweak se siguen notificando sin reescribir sus goldens.

```sh
PYTHONPATH=cloud/workers/python:. python -m unittest tests.test_mtm_tunnel_lite -v
python scripts/apk_analysis/mtm_verify.py /privado/sept.json /privado/remoto.enc --worker
python scripts/android_a24_catalog.py
python scripts/cloud_c0_inventory.py --check
python scripts/cloud_formats_catalog.py
cd cloud/web
node --test tests/mtm-tunnel-lite.test.mjs
```

- JDK `mtm_oracle.java`: aritmética Java int independiente Sj.b/d. Compara
  bytes completos de los dos catálogos reales, sin imprimir credenciales.
- Worker aislado: catálogo y `.v2`, JSON completo igual a referencia real y
  sintética, `isPartial:false`. El worker no descarga.
- Rechazo de JSON duplicado, esquema incompleto, entrada grande, plaintext,
  Base64 roto/truncado. Un catálogo abierto e inválido no invoca e-V2Ray.
- Dos goldens e-V2Ray históricos, cifrado/plain: salida raw idéntica en
  lector original, adaptador compartido y worker. C0 se mantiene congelado.
- Bundle autónomo reproducible igual al archivo comprometido; ejecutado con
  `python -I` fuera del repositorio para archivo y stdin, Unicode, permisos
  0600 y rechazo de sobrescritura. Solo biblioteca estándar.
- CLI autónoma: descarga real completa igual al remoto capturado 37.63.
- Node: ficha e icono, switch persistente sin reiniciar otros proveedores,
  broker autenticado con respuesta completa, rechazo de resultado parcial o
  inconsistente, DNS privada y redirects; TLS verificado.

La metadata `.v2` offline se refiere a e-V2Ray histórico. MTM necesita Cloud
o CLI; no se ha implementado lector Android offline ni ejecutado en móvil.
Falta archivo de actualización MTM real proporcionado por usuario. No hay
cloud import por ID propio identificado. No se despliega VPS ni se publica APK.

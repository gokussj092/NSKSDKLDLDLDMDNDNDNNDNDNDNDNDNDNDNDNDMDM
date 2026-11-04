# Pruebas

10 Python y147 Node correctas. El vector ficticio fue producido por JCA,
incluyendo Base64 con saltos de línea dentro y fuera del sobre GCM, ROT34,
Unicode, campos vacíos y metadatos desconocidos. Negativos: glifos/longitud,
CBC/clave incorrecta, GCM con tag inválido, Base64 interior inválido aunque el
tag sea válido, truncado, HTML, duplicados, NaN, esquema y límites.

Se contrastaron íntegramente remoto107/244/5325 campos y asset1/7/84 campos con
JCA independiente, CLI y worker aislado. La descarga operativa volvió a obtener
HTTP200/4311432bytes y el mismo SHA256. No se guardan perfiles reales en Git.

```sh
python analysis/com.doriaxvpn.unlimited/129/tools/run_checks.py /ruta/privada/checks
```

Node se ejecuta desde cloud/web. Valida destino /new, timestamp, headers
originales, TLS/DNS público, redirects, rechazo de URL del cliente y404 sin
fallback obsoleto, icono original grande, controles y contrato no parcial.
El probe real Node fue denegado por la red; el replay usa HTTP simulado y
ciphertext/worker reales. No constituye prueba de producción en VPS.

[Resultados, negativos y dependencias](../../../../analysis/com.doriaxvpn.unlimited/129/RESULTS.md).

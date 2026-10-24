# Fase 4 — API MKK Hyper: JSON íntegro y límites separados

## Diagnóstico confirmado en la rama

MKK agrega cuatro catálogos HTTPS previamente aprobados: `servers`,
`static`, `subscriptions`, `legacy-subscriptions`.
Había cuatro restricciones diferentes en el flujo del servidor:

1. El empaquetador de fuentes descartaba respuestas cuando la suma superaba
   12 MiB, aunque cada origen aceptaba hasta 8 MiB.
2. El worker aislado solo podía escribir 4 MiB (`RLIMIT_FSIZE`).
3. La función de lectura de salida del worker rechazaba más de 4 MiB.
4. El gateway web solo permitía una respuesta de worker de 6 MiB.

## Correcciones

- **MKK exclusivamente**: el paquete admite hasta **45 MiB** como envoltura
  Base64, suficiente para las cuatro fuentes de hasta **8 MiB cada una**.
  No se eliminan fuentes de forma silenciosa por el antiguo límite conjunto.
  Los demás proveedores conservan sus límites.
- El worker y el bridge MKK admiten **32 MiB de salida JSON UTF-8**. Se
  conservan los límites de CPU y tiempo del proceso aislado y los límites
  de fichero **4 MiB para el resto de decodificadores**.
- La API lee el resultado interno en streaming con un máximo de **96 MiB**
  de envoltura JSON solo para MKK. Esto incluye `rawText` y
  `structuredJson`, por lo que puede ser mayor que la salida JSON original.
  Un resultado superior al límite falla explícitamente; nunca se corta.
- Se valida que el resultado MKK sea **JSON estricto**, con estructura de
  cuatro fuentes, metadatos consistentes y equivalencia entre el JSON de
  `rawText` y `structuredJson`. No se aceptan HTML, logs, JSON incompleto
  ni sobrescritos arbitrarios de metadatos.
- Fuentes remotas fallidas se notifican explícitamente con `isPartial` y
  `PARTIAL_SOURCE_FAILURE`; ningún informe parcial se presenta como completo.
- Pruebas Node: `mkk-hyper-large-result.test.mjs`, además del contrato
  `server-vpn-worker-contract.test.mjs`.
  Pruebas Python: `test_mkk_large_result.py`.

## Restricción importante del cliente Android actual

**Solo se ha modificado la API**. El código Android presente en el PR #96 aún
tiene límites locales que impiden recibir salidas MKK mayores de 4 MiB:

- `android/app/src/main/cpp/spdecode_transport.cpp`:
  `kMaxReplyBytes=6 MiB`.
- `android/app/src/main/java/com/ghostdeveloper/spdecode/cloud/CloudDecodeClient.kt`:
  `text.length>4 MiB` se rechaza para cualquier resultado.

Por tanto, **la API podrá generar y responder** con un JSON válido superior al
límite antiguo, **pero Android todavía lo rechazará**.
Se necesita una actualización Android posterior para soportar estos resultados
con límites por formato, guardado en historial sin una vista previa enorme,
control de memoria, y pruebas en dispositivos modestos. No es viable afirmar
que un cambio exclusivo de la API ya entrega archivos enormes a la app.

## Límites de seguridad y despliegue

No se acepta respuesta literalmente ilimitada: podría agotar RAM/disco del
VPS. Los máximos anteriores son un incremento controlado, específico de MKK.
Una fuente >8 MiB devuelve `REMOTE_TOO_LARGE`; una salida >32 MiB devuelve
`OUTPUT_TOO_LARGE` sin truncamiento. Si los tamaños reales justifican límites
mayores, se requiere presupuesto de memoria, pruebas de carga o entrega
fragmentada/autorizada; no se quitarán protecciones globales.

No se cambia catálogo público, versión de Android, endpoints, consentimiento,
firmas ni contratos para los demás proveedores. Sin merge ni despliegue.
Todos los archivos de esta fase se agrupan en **un commit**, para evitar
repetir GitHub Actions.

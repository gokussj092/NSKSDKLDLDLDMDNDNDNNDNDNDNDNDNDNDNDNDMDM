# Primera comprobación real de descargas

Ejecución: 2026-11-09 05:44 UTC (noche del 8 de noviembre en Tijuana).
Workflow Catalog downloads - warnings only; commit 9d58137527fd5f1cdbbbdda4fbc1ab6a086ff508.
[Ver ejecución 42568911622](https://github.com/gokussj092/NSKSDKLDLDLDMDNDNDNNDNDNDNDNDNDNDNDNDMDM/actions/runs/42568911622).

**Job aprobado con advertencias**: 20 pruebas offline aprobadas; 67 proveedores,
79 entradas de comprobación, 61 descargas válidas, 18 advertencias y cero errores
del comprobador. No se ejecutó ningún descifrador.

| Proveedor / fuente | Observado | Clasificación |
| --- | --- | --- |
| Wolf Custom VPN | HTTP 404 | Fuente remota no disponible |
| Tunneltweak | HTTP 426 | Solicitud rechazada; revisar actualización/protocolo |
| AustroPlus VPN | HTTP 404 | Fuente remota no disponible |
| MKK Hyper / static | HTTP 404 | Fuente auxiliar no disponible |
| MKK Hyper / legacy-subscriptions | HTTP 404 | Fuente auxiliar heredada no disponible |
| CATNET VPN | Sin respuesta HTTP | Fallo de transporte; causa exacta no confirmada |
| Halcon, ALFAISAL, VIP Snipher, NUR | Sin petición de catálogo | Configuración requerida ausente en Actions |
| CREEB, AM Tunnel Lite, UT Loop Pro, ProNeet, EUT, TunelGuard, DTunnel Mod, Royal | Sin ruta habilitada en el broker | Se inventariaron y avisaron; no se inventaron fuentes |

El estado HTTP 426 no demuestra por sí solo qué cambio exige el proveedor.
Los fallos observados no se etiquetan como fallo criptográfico ni método muerto.
En MKK permanecen disponibles las otras fuentes comprobadas; no se declara que
todo su catálogo esté caído.

TunnelDoom y MM Tunnel descargaron con HTTP 200. Esto valida su descarga en
esta ejecución; no valida el descifrado de MM ni su rendimiento en el VPS.

## Referencia inicial

Se registran las huellas de las 61 descargas válidas en
scripts/ci/catalog-download-baseline.json. La referencia describe exclusivamente
el transporte observado, no la corrección de los métodos actuales.

Los candidatos posteriores no actualizan automáticamente esta referencia.
Los cambios de valores/versiones/recuento son informativos; cambios de contenedor
o estructura raíz generan advertencia hasta revisar la referencia.

generated/initial-report.json conserva únicamente metadatos sanitizados. No
contiene URLs de proveedores, cuerpos HTTP, tokens, cabeceras ni contraseñas.

## Reproducción y límites

- Herramienta compartida: scripts/ci/catalog-download-check.mjs.
- Pruebas propias: scripts/ci/catalog-download-check.test.mjs.
- Receta y secretos requeridos: docs/cloud/CATALOG_DOWNLOAD_HEALTH_ACTIONS.md.
- Entorno: Node 22 en ubuntu-latest; sin instalación npm, motor Python, APK o AAB.
- Los descargadores operativos se reutilizan sin modificación.
- La ejecución no actualiza el VPS ni altera switches o mantenimiento.
- La programación diaria solo se activará cuando el workflow llegue a la rama
  predeterminada. En feat/nuevas-integraciones funcionan push, PR y ejecución manual.

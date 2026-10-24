# Comprobación puntual — RJC TUNNEL PRO RJC-6

Fecha: **2026-10-22**. Autorización expresa del usuario para catálogos externos.
Analizados `AbstractC0015Mm`, `HJ.e`, actualización/consumidores de
`OpenVPNClient` y `rjc.vpn.app.activities.a`. La herramienta guardada LSParanoid
resolvió **1504 IDs / 55 archivos / 2102 cadenas** sin ejecutar la app.

| Fuente | Bytes cifrados | Versión | Servidores | Payloads |
| --- | ---: | --- | ---: | ---: |
| HTTPS oficial, HTTP 200 | 783128 | 22.4 | 41 | 1253 |
| Asset `gremlin.json` | 744904 | 15.1 | 46 | 1205 |

SHA-256 remoto:
`7eb51ecca8f0e5cdfe3a7c002344de4fca7f1c9ebd30d98104939a2309d54f68`.
Ambos documentos completos se comparan con el oracle JDK existente
`mx_tunnel_pro_oracle.java`: nueva inspección de este APK confirma que clave,
delta, aritmética y formato son idénticos. Se reutilizan también sus vectores
sintéticos, sin generar datos de prueba con el lector bajo prueba.

El CLI stdin fuera del repo y el worker aislado producen el JSON íntegro de
ambas fuentes, `isPartial:false`. Otra descarga HTTPS real con el nuevo CLI
`--download` coincide con el documento remoto completo de referencia.

**3 comprobaciones Python y 24 web aprobadas**:

```bash
PYTHONPATH=cloud/workers/python:. python -m unittest tests.test_rjc_tunnel_pro -v
cd cloud/web
node --test tests/rjc-tunnel-pro-remote.test.mjs tests/server-vpn-catalog.test.mjs
```

Casos: todas las listas, registros duplicados, Unicode, metadatos/tipos/vacíos,
worker y CLI fuera del repo; rechazo de secciones y registros inválidos, claves
JSON duplicadas, no finitos, Base64/longitud/truncamiento y tamaño excesivo;
fuente exacta, DNS/IP fijados, TLS, IP privadas y redirecciones; ficha, control
de disponibilidad e icono original. `git diff --check` correcto.

PNG original: 105621 bytes, 512×512, SHA-256
`cbfa6c1555e6c9839c915b0e49b381a551099807c28fe1927bd9b33b79fb0476`.
Copiado sin conversión ni redimensionado.

Sin suites completas por petición del usuario. Python HTTPS/CLI y proceso
aislado reales; transporte Node controlado. No se afirma gateway desplegado,
VPS, CI remota, sesión VPN, ejecución Android ni archivo de perfil certificado.
APK, catálogos reales, inventarios de cadenas y resultados con cuentas fuera de Git.

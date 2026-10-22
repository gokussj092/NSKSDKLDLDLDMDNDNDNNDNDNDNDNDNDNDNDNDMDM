# Comprobación puntual — RMP TUNNEL PRO RMP-5

Fecha: **2026-10-22**. Autorización expresa del usuario para catálogos externos.
Analizados `Hm`, `C0195zJ.e`, actualización/consumidores de
`OpenVPNClient` y `rmp.vpn.app.activities.a`. La herramienta guardada LSParanoid
resolvió **1487 IDs / 52 archivos / 2097 cadenas** sin ejecutar la app.

| Fuente | Bytes cifrados | Versión | Servidores | Payloads |
| --- | ---: | --- | ---: | ---: |
| HTTPS oficial, HTTP 200 | 723084 | 9.9 | 40 | 1250 |
| Asset `gremlin.json` | 698936 | 3.8 | 40 | 1211 |

SHA-256 remoto:
`8696d369274b630e733438e89d597d4a55ba384a02859db3c651e2a29ea90579`.
Ambos documentos completos se comparan con el oracle JDK existente
`mx_tunnel_pro_oracle.java`: nueva inspección de este APK confirma que clave,
delta, aritmética y formato son idénticos. Se reutilizan también sus vectores
sintéticos, sin generar datos de prueba con el lector bajo prueba.

El CLI stdin fuera del repo y el worker aislado producen el JSON íntegro de
ambas fuentes, `isPartial:false`. Otra descarga HTTPS real con el nuevo CLI
`--download` coincide con el documento remoto completo de referencia.

**3 comprobaciones Python y 25 web aprobadas**:

```bash
PYTHONPATH=cloud/workers/python:. python -m unittest tests.test_rmp_tunnel_pro -v
cd cloud/web
node --test tests/rmp-tunnel-pro-remote.test.mjs tests/server-vpn-catalog.test.mjs
```

Casos: todas las listas, registros duplicados, Unicode, metadatos/tipos/vacíos,
worker y CLI fuera del repo; rechazo de secciones y registros inválidos, claves
JSON duplicadas, no finitos, Base64/longitud/truncamiento y tamaño excesivo;
fuente exacta, DNS/IP fijados, TLS, IP privadas y redirecciones; ficha, control
de disponibilidad e icono original. `git diff --check` correcto.

PNG original: 69948 bytes, 512×512, SHA-256
`c00e5d70987cf08e1b868be5800962569abd16e98f86d9e4bc999f71e1405527`.
Copiado sin conversión ni redimensionado.

Sin suites completas por petición del usuario. Python HTTPS/CLI y proceso
aislado reales; transporte Node controlado. No se afirma gateway desplegado,
VPS, CI remota, sesión VPN, ejecución Android ni archivo de perfil certificado.
APK, catálogos reales, inventarios de cadenas y resultados con cuentas fuera de Git.

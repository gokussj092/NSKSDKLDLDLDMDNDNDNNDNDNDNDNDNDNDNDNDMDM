# Comprobación puntual — Mx Tunnel PRO Mx-Build48

Fecha: **2026-10-22**. Autorización externa explícita del usuario.
Inspeccionados `Dm.a/b/c/d/f/g`, `DJ.e`, consumidores de campos y tabla
LSParanoid del build 48. Se recuperó la receta sin ejecutar la aplicación.

| Fuente | Bytes cifrados | Versión | Servidores | Payloads |
| --- | ---: | --- | ---: | ---: |
| HTTPS oficial, HTTP 200 | 729536 | 564 | 39 | 1467 |
| Asset `gremlin.json` | 704128 | 497 | 51 | 1396 |

SHA-256 cifrado remoto:
`8206fa868065fdf9d20958332e7f271e28b381bb62a479be27354e6db0e17df2`.
SHA-256 asset:
`4428e96cc7d9573a64e42bfb2efb801e5f7521fefb9a552e5301c1c66a4b94c3`.
Los JSON íntegros de ambos orígenes coinciden con `mx_tunnel_pro_oracle.java`,
transcrito de la aritmética Java del APK. El nuevo CLI con stdin fuera del repo y
el worker aislado coinciden con ambos documentos, `isPartial:false`. El CLI
`--download` realiza otra descarga HTTPS real y devuelve el mismo catálogo remoto.
Salida remota renderizada: **691416 bytes**, dentro del presupuesto del worker.

```bash
PYTHONPATH=cloud/workers/python:. python -m unittest tests.test_mx_tunnel_pro -v
cd cloud/web
node --test tests/mx-tunnel-pro-remote.test.mjs tests/server-vpn-catalog.test.mjs
```

**3 pruebas Python y 21 pruebas web aprobadas**. Casos: todas las listas,
duplicados de registros, Unicode, campos desconocidos y tipos; worker y CLI;
rechazo de documentos malformados, claves JSON duplicadas, números no finitos,
secciones inválidas, truncamiento y tamaño excesivo; fuente fija, TLS, DNS/IP,
direcciones privadas y redirecciones. El mismo caso de compatibilidad verifica
que el vector histórico HX continúa abriéndose con su clave predeterminada y
que no acepta el catálogo Mx. Otras **4 comprobaciones puntuales TRV/4U** verifican catálogos y fingerprints
de sus dependencias actualizadas. No se ejecutan suites completas por petición del usuario.

Herramientas preservadas en `scripts/apk_analysis/`: inspección del APKS real,
JADX fijado mediante checksum sobre `classes3.dex`, LSParanoid (**574 IDs / 44
archivos / 2115 cadenas**) y patrón Random del MegaTunnel anterior (**3306
literales / 89 archivos**). El inventario nuevo coincide con el análisis anterior.
No se publica el inventario ni su contenido. El instalador de JADX se fija contra
checksums de la publicación oficial; esta comprobación usó el JAR local verificado.

HTTPS externo real por Python; transporte Node controlado. No se afirma sesión
VPN, Android, gateway desplegado, VPS o CI remota aprobada. No se incluyen APK,
SO/JAR, respuestas reales, cuentas o resultados descifrados en Git. Integración
de catálogo, sin certificación de un archivo de perfil exportado.

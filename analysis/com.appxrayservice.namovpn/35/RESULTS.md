# Resultados actuales — corrección de campos 2026-11-04

**VERIFIED_REAL:** catálogo 22.3, 14 Servers y 13 Networks; GET original
HTTP 200, text/plain UTF-8, 72881 bytes, SHA256
`578ad82fed747a2670a8fe4fb0abaeda16df60684581bec0a7e10e2d47aeee06`.
Se decodifican 87 valores internos, manteniendo todo el documento. Referencias
Java independientes para XXTEA y Base64/UTF-8 iguales a Python, CLI y worker
completos en dos descargas. Hash canónico del JSON final:
`339be291594ac0b6fb587abe594693c092dc4c3c335d15eb0599375da2b1963c`.
Los perfiles reales permanecen fuera de Git.

**Corrección de evidencia:** el verificador anterior solo abría el sobre. Sus
resultados no demostraban que los campos fueran legibles. Se retira la afirmación
anterior de interior en texto. [Trazado completo](FIELDS_FIX.md).

**VERIFIED_SYNTHETIC:** 15/15 pruebas Python y 172/172 Node en 20 archivos.
Fixture ficticio de ambas capas generado por Java, todos los campos explícitos,
alias y raíz, Unicode/CRLF, padding/whitespace, vacíos/faltantes, decodificación
única y claves futuras intactas. Se rechazan 33 combinaciones de campos con
alfabeto/padding/tipo/UTF-8 inválidos, además de los negativos del sobre,
esquema, tamaños, clave, HTML, duplicados y NaN. Worker rechaza un campo corrupto
sin resultado parcial ni filtración. Regresiones de descarga/contrato, TLS/DNS,
redirects, switches, HTTP Conexión/Firebase y fichas/versiones pasan.

Primer pase de esta revisión: Python 14/14 y Node 104/150 (46 fallos). El
workspace parcial carecía del icono Genis, fixtures y módulos HTTP Firebase.
Se restauraron bytes exactos de la revisión Git base; después Node 172/172.
Pase final conjunto con el nuevo negativo de worker: Python 15/15 y Node 172/172.
No se modificó producción ni se suavizaron pruebas para ocultar esas ausencias.

**SIMULATED_HTTP_REAL_BYTES:** replay Node con ciphertext y worker reales pasa.
**NETWORK_UNAVAILABLE:** Node HTTP real retorna REMOTE_NETWORK_DENIED aquí;
VPS y rollout siguen pendientes. La descarga Python sí es HTTP real.
No se certifican cuentas/conexiones VPN, archivos, texto, importación/exportación
ni compatibilidad universal con builds futuras. XXTEA no autentica; el backend
rechaza Base64/UTF-8 inválido más estrictamente que Android.

Se conservan herramientas históricas y los negativos iniciales: JADX 1.5.6
exit 3/40 errores; icon.png del XAPK era JPEG y el extractor v1 lo rechazó;
primer test Node original tenía una expectativa de URL errónea, corregida en
la integración inicial. No se certifica equivalencia de firma con Play.

CPython 3.12.14, OpenJDK 17.0.20+8, Node 24.22.1, Linux x86_64 y locks existentes;
sin paquetes nuevos. Herramientas manuales, licencias transitivas/Fase7 pendientes
de revisión; bloqueo CI de evidencias aún no implementado. Piso 71/65 fichas/256
formatos; se preservan versiones VPS mayores. Solo Cloud, sin Android, merge ni
despliegue. Evidencia sanitizada en generated/fields.json y MANIFEST.

El wrapper nuevo de captura falló primero porque el auxiliar se llamaba
inspect.py y ocultaba inspect de stdlib al cargar pyelftools. Se renombró
inspect_fields.py; no cambió el algoritmo ni se añadió una dependencia.

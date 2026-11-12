# Resultados Litron Pro11

VERIFIED_REAL para catálogo de com.litron.udp, separado de Litron base. Remoto HTTP200/31768bytes, versión2.6.7:51 servidores,206 campos internos. Incluido15384bytes, versión1.0.0:26 servidores/104 campos. JCA independiente, Python y worker real coinciden en el JSON entero, rawText y structuredJson; isPartial=false, sin paginación ni truncado. Salida remota22084bytes e incluida10731bytes.

SHA-256 canónico remoto38f611754037f1cb7834988df83281ce1ad37cfcc7e9f34b51b0a557516e96c2; incluido f615bd04116ee82e44e58da5348c9447393d3b7f1e901e7c92f562b61257277d. Los cuerpos reales siguen privados. Las pruebas de apertura completa no prueban autenticidad: CBC no está autenticado.

Icono original del APKS: PNG500x500,165852bytes, SHA-256625e93856e82f750a0a4590537aac184d8c9110a13877c446d2dcff9a043a887. Copias idénticas en app decodificadora y web. No se reutiliza el icono de Litron base.

Las13 pruebas Python/3 Node nuevas usan fixtures JCA ficticios para claves observadas, valores vacíos, JSON/Unicode inválido, duplicados/no finitos, límites5MiB entrada/4MiB salida, preservación de campos y separación base/Pro, CLI/worker, fuente fija, icono exacto, TLS/DNS y denegación de redirecciones/IP privada. No acreditan por sí mismas un servidor externo.

JADX1.5.6 completo reportó6078 errores y salió3; se pudo trazar y comprobar el camino del catálogo, sin afirmar decompilación global completa. Androguard4.1.3 solo leyó metadatos/certificado; firma criptográfica global no verificada. No se ejecutó APK/DEX/SO ni sesión VPN. No se certificó formato de archivos/exportación de teléfono. Sin paquetes nuevos, APK compilado, merge main o despliegue VPS.

Regresión local final:101 Python y196 Node correctas,20 pruebas del arnés correctas y npm run build correcto. Suite completa y dependencias mínimas en .github/workflows/catnet-litron-catalogs.yml. El primer ensayo negativo de redirección Pro detectó que el broker heredado permitía otra ruta del mismo dominio; se agregaron ambos Litron a la denegación total y se amplió también la prueba de base. La regresión final pasó sin modificar métodos ajenos.

A0 sin bloqueos; P06 PASS_WITH_UNRESOLVED:7 fuentes de método cambiadas,85 fuentes alcanzadas,17 expedientes y46 consumidores sin resolución estática. Nueve expedientes exigidos por P06 y el expediente base incluyen revisión de consumidores; los casos sin resolver no se consideran aprobados. El control global de descargas descubre Pro automáticamente y conserva su regla de solo descarga/advertencias, sin descifrar catálogos.

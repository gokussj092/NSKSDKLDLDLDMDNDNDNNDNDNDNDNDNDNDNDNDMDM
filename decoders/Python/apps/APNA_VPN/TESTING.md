# APNA VPN 3.9 — validación del catálogo

## Muestra real (23 octubre 2026)

- APK/APKS de usuario, sin incorporar sus bytes, JSON, contraseñas, hosts ni payloads a Git.
- Asset assets/janu.json: 281096 bytes Base64; SHA-256 620e4aa2cd5c4ec6cb1d2015b4bfdec172050bcdb8e1b5e4187f026563e5a94a.
- Base64 contiene 210820 bytes binarios XXTEA modificado.
- JSON íntegro descifrado: 210815 bytes UTF8, Version 289, 19 servidores gratuitos, 491 payloads, 10 secciones.
- Un cifrador XXTEA independiente reconstruyó los 210820 bytes binarios originales byte por byte a partir del JSON recuperado.
- CLI sobre el APKS real con --summary terminó con código 0 y recuentos idénticos.
- Reversibilidad exacta **no significa** que el archivo cuente con MAC o firma criptográfica.

## Pruebas automatizadas sintéticas

    PYTHONPATH=. python -m unittest tests.test_apna_vpn -v

Tres casos locales aprobados: reversibilidad con cifrador independiente, JSON anidado Unicode, errores de Base64/ciphertext/formato y resumen CLI sin exponer contraseñas de prueba.

## Pendientes

No se confirmó fuente HTTPS oficial de catálogo remoto ni el icono del proveedor; no hay descargas públicas, edición Android, APK nueva, despliegue VPS ni publicación de novedades. El motor privado solo descifra bytes de catálogo suministrados por una ruta autorizada. Las suites globales y la integración Android no fueron ejecutadas localmente.

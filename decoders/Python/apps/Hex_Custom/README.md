# Hex Custom 10.6.1 (101) — método de archivo pendiente

Paquete `com.hex.custom.jotchuast`. Alcance solicitado: **solo archivos**.
El APKS se analizó y se guardaron herramientas reproducibles; todavía **no hay
un decodificador de archivos funcional**. No se ha registrado una extensión ni
se ha cambiado el catálogo Server VPN.

El exportador/importador actual es `CustomServerShare`. Sus diez métodos,
incluidos `doubleEncrypt`, `doubleDecrypt`, `sign`, `exportToDocuments` e
`importFromUri`, están sustituidos por wrappers ARM64 que llaman a una máquina
virtual de **KOV-SEC**. La tabla de métodos y su pool de cadenas se recuperaron;
la igualdad de **546488 bytes** se verificó ejecutando solo el bucle XOR aislado
de la biblioteca original. Esto no equivale a recuperar los cuerpos virtuales.

También se separaron los tres paquetes de `assets/protection/kov-sec.dat`, con
sus límites y hashes. Permanecen opacos/protegidos: no se presentan como DEX o
código descifrado. El contenedor conserva una firma de 64 bytes; la herramienta
no afirma haber verificado esa firma ni ejecuta la VM de protección.

## Estado de archivos y contraseña

- Extensión real: **sin confirmar**; no registrar `.hex`, `.hc` u otra por nombre.
- Capas, claves, KDF y firma del archivo: **sin recuperar**.
- Contraseña adicional obligatoria: **sin confirmar**. ShareOptions tiene
  bloqueos por ID/compañía/root, caducidad y UUID, pero no un campo password.
  Eso no demuestra que el segundo parámetro de doubleDecrypt sea prescindible
  ni que esos bloqueos sean únicamente posteriores al descifrado.
- No se proporcionó una exportación real: falta contrastar el formato y el
  resultado. Un archivo de muestra será útil para la siguiente investigación.

No se reutiliza el método HTTP Custom, AboWaged, CREEB o una biblioteca antigua
incluida solo por coincidencia de nombre. `native-methods.json` guarda únicamente
estructura y direcciones, sin configuraciones privadas o binarios de la app.

Ver `ANALYSIS.md`, `TESTING.md` y `scripts/apk_analysis/RESTORE.md` para continuar
con el mismo APKS. Herramientas y análisis guardados en PR #96; sin activación,
despliegue, APK modificada ni cambios Android/C11.

# Fixtures — Fx Tunnel 4.8

Todos SINTÉTICOS. Nombres de servidor y payload inventados
(`TEST-...`, hosts en `203.0.113.0/24`, dominio `example.org`).
Ningún valor real de servidor, ninguna contraseña de usuario, ninguna
credencial: la única constante criptográfica del método real es la
clave XOR de 12 bytes de los `.fxt`, que vive en el script operativo
y NO se copia aquí (los tests de round-trip la ejercen a través del
script operativo).

- `synthetic_catalog.json` — catálogo sintético con la misma forma
  (Version, Free_servers, Payloads) para probar la validación
  estructural `_catalog_json`. No es un catálogo real.
- `synthetic_profile.json` — perfil `.fxt` sintético para probar el
  round-trip cifrar → descifrar a través del script operativo.

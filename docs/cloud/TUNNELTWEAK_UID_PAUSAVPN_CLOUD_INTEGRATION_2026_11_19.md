# SP-DECODE Online — Tunneltweak Cloud UUID + PausaVPN (M Light)

**Rama:** `ci/unity-ads-online-qa` · **Catálogo:** 92 → **93** · **Fecha:** 2026-11-19  
**Compatibilidad:** clientes existentes, V2 HPKE, PoP, Play Integrity, controles de proveedor, catálogo Server VPN, `.tut`, `.pausa`.

## Objetivo y decisiones

- La pantalla **Nube (Online)** acepta UUID de 36 caracteres `8-4-4-4-12` y `tunneltweak://<uuid>`. La detección automática atribuye provisionalmente el UUID a **Tunneltweak Cloud**, porque es el único importador Cloud-UUID permitido actualmente. **Un UUID no permite inferir criptográficamente su aplicación de origen**. Antes de añadir un segundo importador UUID, introducir selector explícito y pruebas de no-colisión.
- El Android **no recibe URL ni secretos del proveedor**. Solo remite `{provider:"tunneltweak",reference:"<uuid>",consent:true}` mediante la **operación 7** sobre HPKE V2 autenticado. Las operaciones 1/2 de sesión permanecen intactas; no insertar versión, installer o UUID en SESSION.
- `cloud/web/lib/c35-gateway.mjs` detecta y autoriza el proveedor `tunneltweak`, respeta el switch de Servidores VPN y el de mantenimiento de archivos, sesión, cuotas de decode y consentimiento. El código no acepta URL arbitraria, body personalizado ni cabeceras de red aportadas por Android.
- `cloud/web/lib/c35-provider.mjs` construye en el servidor la URL fija `https://tunneltweak.com/api/cloudconfig/<uuid>`; usa el User-Agent verificado del proveedor, HTTPS con verificación TLS, DNS public-only con IP fijada, sin redirecciones, con límite de 8 MiB y JSON externo con `config` string. El payload real se entrega exclusivamente al worker aislado.
- El worker Python decodifica esa envoltura `{config: <perfil cifrado>, ...metadatos}` mediante el lector de **Tunneltweak 6.2.3**, compatible con `config_version` 6 y 7, preservando los otros campos. Usa la ruta protegida `tut` existente: los lectores DES/CBC/XOR/TTPBE1 históricos de archivos `.tut` siguen operando sin cambios. En `PASSWORD_REQUIRED` se retorna una sola vez el blob descargado a Android por HPKE para el diálogo RAM-only; no hay segunda descarga.
- **PausaVPN (M Light)** mantiene el ID persistente `m-light`, el motor `M_Light.py` para catálogo, `M_Light_archivos.py` para archivos `.pausa` y el prefijo `pausa://`. El cambio es de *nombre público* en el inventario supplied, `file-formats.json` y `text-formats.json`. Los favoritos e IDs de caché siguen estables.
- La lista Android filtra por `name` o `id` de forma case-insensitive, por lo que ahora se podrá buscar **PausaVPN** o **M Light**. No se requiere añadir otra app ni duplicar el ID en el catálogo.
- La versión del catálogo cambia una sola vez a 93, incluso si también se actualizan iconos/metadatos en el mismo lote.

## Verificación realizada y pendiente

**Pruebas reproducibles en GitHub Actions:** `cloud/web/tests/c35-import-security.test.mjs` (UUID válido/ilegítimo, protocolo fijo, DNS/IP, no-redirect, consentimiento, sesión, dispatch, metadata y handoff de contraseña); `tests/test_tunneltweak.py` (envolturas y contraseña a través del motor aislado, archivos históricos), `android/app/src/test/java/com/ghostdeveloper/spdecode/cloud/CloudOnlineReferenceTest.kt`, `cloud/web/tests/supplied-integrations.test.mjs` (ficha, ID, formatos), `M_Light.py --self-test` y `M_Light_archivos.py --self-test`. Se usan UUID sintéticos y nunca un UID real de un usuario en los fixtures.

**Límite de evidencia:** los self-tests de PausaVPN usan muestras sintéticas para archivos y enlaces. Falta validar un `.pausa` genuino exportado por la app oficial. La descarga real del catálogo M Light se verificó previamente (117 servidores el 2026-11-17), pero el contenido remoto puede cambiar. La prueba CI del nuevo importador UUID usa transporte controlado y no demuestra por sí sola que todos los UUIDs reales del proveedor continúen disponibles.

## Despliegue en VPS (ambos contenedores, no solo web)

```bash
sudo spdecode backup
sudo spdecode update all <COMMIT_VALIDADO_POR_CI>
sudo spdecode status
sudo spdecode logs api
sudo spdecode logs worker
```

El nuevo servidor/worker debe instalarse **antes de comprobar el UUID en el APK**, porque los APK antiguos no contienen el detector ni la operación 7 con este proveedor. No eliminar bases de datos, cachés, firmas, keyrings HPKE, volúmenes ni reseteos de límites para desplegar esta integración. Después de instalar el APK release firmado, probar: UUID en Nube (Online), `tunneltweak://`, catálogo PausaVPN por búsqueda, descarga autorizada, `.pausa` y error de contraseña. No enviar perfiles, credenciales ni tokens en logs o tickets públicos.

## Guía para otras IA

1. **Nunca** añadir campos a SESSION V2 ni relajar los validadores HPKE o PoP por un error de importación; releer [postmortem V2](INCIDENTE_V2_ANDROID_CLOUD_Y_CATALOGO_2026_11_18.md).
2. `Tunneltweak` (catálogo) y `Tunneltweak Cloud UUID` (archivo/Cloud wrapper) usan **fuentes y cuerpos distintos**. No enviar un Cloud JSON al lector de catálogo ni descifrarlo en Android.
3. `PausaVPN` y `M Light` son **la misma aplicación**; no duplicar el ID, catálogo, credenciales ni formatos. No sustituir el motor `.pausa` AES-CBC/Baybayin por la entrada C0 genérica AES-GCM.
4. Nuevos proveedores con UUID requerirán identificación explícita, una lista estricta de hosts, separación de permisos y pruebas de migración del cliente. No deducir la aplicación de 36 caracteres.
5. Mantener el número del catálogo monotónico y documentar evidencia de descarga real por proveedor sin incluir URLs privadas, resultados descifrados ni identificadores reales de usuarios.

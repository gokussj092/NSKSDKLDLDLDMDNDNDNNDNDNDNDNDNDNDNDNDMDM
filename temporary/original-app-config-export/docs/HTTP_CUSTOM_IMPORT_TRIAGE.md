# TEMPORARY — HTTP Custom HCX4 import-failure triage

## Resultado observado (no reinterpretar)

- Entrada: `3 long grok.hc`, 4,230 bytes, SHA-256
  `167593e228e10c3eaa98333198f0c1c946f328b7b99ab2ef574bc429576ca4ba`.
- Esquema autenticado por SP-DECODE: HCX4 / HCCFG 10, `n11`, build 899,
  una sección `i` de configuración principal y una `j` de perfil.
- JSON de lectura principal: `main`, perfil `config[0]`, vista derivada
  `protections`; la vista no contiene todos los campos binarios del sobre.
- Modificaciones solicitadas: `main.g.a: "lock_all" -> false`,
  `main.g.v` se convierte en nota/créditos SP-DECODE,
  `main.u` se cambia a `https://spdecode.xyz`; los demás datos se conservan.
- Archivo reencriptado histórico: 4,207 bytes, SHA-256
  `78d257386e9a50cc4548f44df0d67cdb37526941952ebcf490a66f6d74ee6f6f`.
- **Resultado en el importador original: se descifra, pero rechaza el formato
  JSON** (informado por el propietario).
- Por tanto, `roundtrip_verification.json` prueba autenticación local; **NO
  demuestra importación válida**.

## Hipótesis priorizadas

1. **Tipo de `main.g.a`**: el valor original es un **string**
   (`"lock_all"`), mientras el nuevo es un **booleano** (`false`).
   Puede ser un enum textual que el parser original no acepta como booleano.
   No asumir que basta "false"; obtener opciones legítimas de un exportado
   creado y desbloqueado desde HTTP Custom original.
2. **Campo `main.u`**: era una dirección remota de actualización, ahora apunta
   a una portada web. No se ha probado si el importador exige contenido de
   actualización de un formato específico, aunque probablemente sea consumo
   posterior. Aislar este cambio.
3. **`noteEnabled` y nota**: el texto existe en `main.g.v`; el campo
   opcional `main.g.e` no existía en la muestra. No inventarlo sin comprobar
   en una exportación legítima. Una imagen/banner no está implementada como
   campo gráfico de HCX4.
4. **Representación JSON**: `codec.decrypt()` es un lector, no un exportador:
   normaliza `protections`, convierte secciones y no devuelve todos los campos
   criptográficos/serializados del sobre. Construir `.hc` desde el JSON de
   presentación puede perder información. El script actual evita sustituir
   `j`, conserva el sobre y sólo re-cifra la sección `i`, pero no demuestra
   paridad de aceptación de JSON por la app.
5. **Compatibilidad por versión/exportador**: la prueba usa build 899, HCX4
   HCCFG10/n11 sin contraseña/HWID. No extrapolar a HCX1-3, n12, o archivos
   protegidos.

## Matriz de prueba en el IMPORTADOR ORIGINAL

Probar solo con configuraciones creadas o editadas con autorización,
conservar fuente intacta y exportar con nonces aleatorios. Preparar un archivo
independiente para cada fila:

| Caso | `g.a` | `g.v` | `main.u` | Propósito |
| --- | --- | --- | --- | --- |
| A: rewrap sin cambios | string original | original | original | Baseline: aislar si el reencriptado/serialización ya falla |
| B: solo nota | string original | personalizada | original | Determinar si la nota es válida |
| C: solo URL | string original | original | personalizada | Determinar si URL rompe importación |
| D: solo tipo de bloqueo | `false` | original | original | Validar hipótesis del tipo de `g.a` |
| E: combinación | `false` | personalizada | personalizada | Reproducir el fallo reportado |

Registrar **mensaje exacto**, captura sin secretos, build real de la aplicación,
SHA de cada muestra, si reconoce el fichero, si acepta JSON y si conecta.
No intentar modificar permanentemente protecciones de archivos ajenos o
falsificar la identidad del exportador. Los controles de seguridad del
proveedor siguen siendo responsabilidad del importador.

## Criterios de paso

1. El motor Python autentica HCX4 exterior y sección `i` con AEAD.
2. La sección de perfil `j`, los sidecars, campos desconocidos y credenciales
   permanecen sin cambios en las pruebas de modificación selectiva.
3. Una exportación **sin cambios** re-importa en el HTTP Custom original.
4. El app original re-importa los cambios autorizados y muestra la nota esperada.
5. No se acepta la validación local como sustituto de 3 y 4.

## Integración futura (no implementada)

Solo tras confirmar la matriz anterior, estudiar el componente separado
`exporters/http_custom/` con pruebas y control de consentimiento. No
alterar `decoders/Python/HTTPCUSTOM.py`, worker Cloud, ruta Android, catálogo
ni versionCode en la rama temporal.

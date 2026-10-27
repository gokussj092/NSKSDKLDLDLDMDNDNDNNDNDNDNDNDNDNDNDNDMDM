# Archivos de prueba del banner — Dark Tunnel 1.0.26

**Resultado posterior del propietario, 2026-10-27: añadir el banner bloquea
la configuración. No incluir banner en las exportaciones abiertas Dark Tunnel.**
Este documento conserva el ensayo histórico. El generador exige ahora
`--reproduce-locking-banner`; sin esa opción se detiene antes de crear archivos.
La decisión está en `results/banner_owner_decision_2026-10-27.json`.

Fecha: 2026-10-27 (America/Tijuana). Rama temporal existente, cuenta Goku.
El paquete previo entregaba un control de nota en texto, pero no las variantes
con banner HTML. Esta entrega completa esa prueba pendiente. El reporte manual
de los archivos anteriores se mantiene; los nuevos banners siguen pendientes.

| Archivo | Uso |
| --- | --- |
| `01_CONTROL_NOTA_TEXTO.dark` | Control anterior con créditos de texto, sin HTML |
| `02_BANNER_COMPATIBLE.dark` | Títulos, negritas, colores de fuente y enlaces básicos |
| `03_BANNER_AMOLED.dark` | Diseño AMOLED con el HTML/CSS existente de SP-DECODE |
| `02_BANNER_COMPATIBLE.txt` | Token exacto de 02 para importar como texto |
| `03_BANNER_AMOLED.txt` | Token exacto de 03 para importar como texto |

Probar primero 02 y después comparar 03. Revisar visibilidad, tamaño, espaciado,
enlaces del sitio/canal/comunidad/desarrollador y acceso al editor. Si la nota
no se ve, revisar la opción de mostrar el mensaje de configuración. Los TXT
son transportes alternativos de la misma configuración. El control 01 permite
separar un rechazo de importación de un problema visual del HTML.

## Campo y renderizador observados

Se modifica solo `LockedAppConfig.Message` en el contenedor **ya existente** de
`controls/VLESS_artificial_note.dark`, del paquete privado anterior. Conserva
los datos de la referencia VLESS; ese control era artificial, no una nueva
exportación capturada de la aplicación. No se inventa un campo en el JSON
abierto ni se le añade silenciosamente una envoltura de protección.

Ruta comprobada en los cuerpos decompilados del APK:

1. `C4971` obtiene el mensaje mediante `Ca.d()` cuando existe el contenedor.
2. `AbstractC5134` lo pasa a `AbstractC4749.m11071` como `configLockedMessage`.
3. El mensaje no vacío se presenta mediante `m11069` y `C4774`.
4. `C4774` elimina CR, sustituye LF por `<br />` y llama a `AbstractC3372.m9571`.
5. `m9571` usa **`Html.fromHtml(str, 0)`** para crear el texto Compose.

Esta ruta no utiliza el WebView de anuncios del APK. No es un navegador CSS
completo: gradientes, fondos, bordes, tablas o botones del diseño AMOLED pueden
mostrarse parcialmente. Por ello se entrega también HTML básico. Se retiran
los saltos de formato de las plantillas antes de cifrar la nota, para que la
aplicación no los convierta en espacios verticales adicionales.

El HTML acredita SP-DECODE, Ghost Developer y Ghost Nexora Studio y contiene
los enlaces oficiales. No usa imágenes remotas, scripts ni peticiones de red
automáticas. La inspección del renderizador no prueba la apariencia en Android.

## Preservación y comprobaciones

- Ciphertext interior y plaintext de conexión idénticos al control.
- Mismas banderas, tipos, parámetros de protección y `ConnectedMessage`.
- Bytes MessagePack ajenos a `Message` y JSON ajeno al valor cifrado preservados.
- Seis pruebas nuevas y 25 regresiones Dark Tunnel pasan: **31 en total**.
- 48 comprobaciones CFB con el segundo backend en los tres `.dark`.
- Copias TXT idénticas a sus archivos 02/03; archivos nuevos con permisos 0600.

Esta prueba conserva la envoltura del control, por lo que también se debe
comprobar el editor en el teléfono. No se declara que el banner y la ausencia
total de bloqueos estén validados simultáneamente por conservar las banderas.
La importación de estos nuevos archivos, el renderizado y los enlaces siguen
**pendientes de prueba manual**. Los binarios y textos privados no se suben a Git.

Resultados: `results/dark_banner_samples_2026-10-27.json`.

## Reproducir

Desde el checkout completo, con `requirements-dark-lab.txt` instalado:

```bash
python temporary/original-app-config-export/scripts/test_dark_banner_lab.py -v
python temporary/original-app-config-export/scripts/create_dark_banner_matrix.py \
  --source /ruta/privada/controls/VLESS_artificial_note.dark \
  --output-dir /ruta/privada/banner-nuevo --reproduce-locking-banner
```

Conservar la fuente intacta y registrar para cada variante: importa, banner
visible, enlaces funcionales y editor accesible. No incluir credenciales en
capturas ni registros compartidos.

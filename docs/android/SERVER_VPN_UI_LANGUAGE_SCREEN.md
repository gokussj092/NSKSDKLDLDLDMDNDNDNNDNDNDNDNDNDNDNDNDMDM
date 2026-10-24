# Server VPN — mejora de controles e idioma en pantalla completa

Rama: `feat/austroplus-vpn-13-0-1-decoders`. PR #96.

## Pantalla Server VPN

- Conserva la descarga **manual forzada** del catálogo (icono Refresh circular
  en el encabezado de Servidores VPN, `server_vpn_manual_refresh`). Se desactiva
  mientras hay una carga o decodificación y muestra indicador de progreso.
- El botón manual ya **no** muestra la etiqueta `Nuevo`.
- La etiqueta localizada `Nuevo` se muestra exclusivamente dentro de las
  tarjetas de los proveedores **detectados por primera vez tras un catálogo
  previamente conocido**, junto a favoritos. Estilo pequeño, lavanda y alto
  contraste. No se asigna por orden, nombre o capricho.
- La lógica existente `ServerVpnNewBadges` mantiene la caducidad de dos horas
  basada en `System.currentTimeMillis()` del teléfono. La versión inicial del
  catálogo constituye la línea base; no se marcan automáticamente todos como
  nuevos durante la primera instalación. Reabrir la pantalla o refrescar una
  versión idéntica no reinicia la etiqueta.
- Se rediseñan el buscador (placeholder), chips y botón circular conservando la
  paleta AMOLED y controles accesibles. Los iconos originales siguen intactos.
- Cuando el servidor añade una aplicación, **debe aumentar catalogVersion**;
  de lo contrario la API puede responder `unchanged` y ningún cliente podrá
  conocer el nuevo ID.

## Pantalla de idiomas

- La fila **Ajustes → Idiomas** abre `LanguageSelectionScreen`, una
  pantalla completa en el área de contenido y no un `ModalBottomSheet`.
- Se muestra una lista desplazable de **Sistema + 14 idiomas**, con nombres
  nativos, insignias de región, selección de alto contraste y botón Atrás.
- La barra inferior permanece disponible, con **Ajustes** activo.
- El botón Atrás de Android cierra la subpantalla usando `BackHandler`.
- La preferencia y `MainActivity.setLanguage()` conservan el mecanismo anterior:
  al cambiar la selección la Activity se recrea con el idioma correcto. No se
  altera el almacenamiento ni el tráfico Cloud.
- Nueva cadena `language_screen_title` localizada en 14 conjuntos de recursos.

## Pruebas y entrega

- `LanguageSelectionScreenInstrumentedTest.kt`: navegación, selección y lista.
- `test_android_vpn_directory_language_navigation.py`: controles/ubicación
  del distintivo y ausencia de hoja modal.
- `docs/cloud/C0_UI_BASELINE.json`: rebaseline explícito únicamente para
  `SpDecodeApp.kt` y `FunctionalSettingsPanel.kt`. Sigue verificando nueve
  fuentes congeladas; no se desactiva la comprobación.
- Todos los cambios de esta intervención deben publicarse en **un commit** del
  mismo PR. No se despliega al VPS ni se publica automáticamente en Play Store.

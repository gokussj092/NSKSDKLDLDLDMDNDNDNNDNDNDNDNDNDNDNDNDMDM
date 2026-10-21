# SP-DECODE — Fase 3: cinco idiomas nuevos (Android)

PR: #96, rama `feat/austroplus-vpn-13-0-1-decoders`.

## Idiomas

| Idioma | Código Android | Nombre en selector |
|---|---|---|
| Turco | `values-tr` / `tr` | Türkçe |
| Vietnamita | `values-vi` / `vi` | Tiếng Việt |
| Hindi | `values-hi` / `hi` | हिन्दी |
| Japonés | `values-ja` / `ja` | 日本語 |
| Italiano | `values-it` / `it` | Italiano |

Se han añadido los cinco a `SupportedLanguages`. La Activity ya aplica
`Locale.forLanguageTag(tag)` y recrea la pantalla para conservar el idioma
en preferencias, sin alterar el historial cifrado ni las credenciales.

Se añadieron los siete archivos de recursos Android por idioma:
`strings.xml`, `cloud_error_strings.xml`, `cloud_legal_strings.xml`,
`cloud_diagnostics_strings.xml`, `cloud_history_strings.xml`,
`catalog_update_strings.xml` y `server_vpn_directory_strings.xml`.

## Alcance y control de calidad

- Hay 280 claves de cadena en los recursos ingleses de referencia. En esta
  tanda, **278 de las 280 claves** tienen traducción específica en cada idioma.
  Las **dos restantes** son identificadores literales que deben mantenerse
  iguales en cualquier idioma: el nombre del producto `SP-DECODE` y el
  ejemplo de extensión `profile.tls`. Los textos están traducidos, aunque se
  recomienda revisión lingüística nativa de los cinco idiomas antes de
  afirmar localización editorial definitiva.
- Se mantienen los marcadores `%1$s`, `%1$d` y demás marcadores del
  recurso original. Los textos no traducidos siguen disponibles en inglés,
  evitando avisos vacíos o recursos inexistentes.
- Incluye los textos principales del selector, navegación, Server VPN,
  buscador, favoritos, «Nuevo», consentimiento Cloud, errores principales,
  contraseña, historial y acciones de archivo.
- El catálogo de funciones y formatos no se modifica. Un nuevo idioma **no**
  significa soporte automático para extensiones desconocidas por el cliente.
- Las novedades remotas dependen del idioma admitido por el servidor; no se
  añaden traducciones al backend en esta fase. Comprobar cómo se resuelve el
  idioma de las novedades y aplicar fallback seguro cuando corresponda.
- Prueba instrumentada: `NewLanguagesInstrumentedTest.kt` valida cinco
  códigos de idioma, recursos reales, avisos y sustitución de marcadores.
- QA manual obligatoria en pantalla pequeña, RTL existentes (árabe y persa),
  selección/cambio de idioma, consentimiento, diálogos AMOLED y textos largos.

## Publicación eficiente

Los cambios de los cinco idiomas se preparan en un árbol Git y se publican
mediante **un solo commit y una sola actualización de la rama** para evitar
disparar decenas de ejecuciones de GitHub Actions. No fusionar, desplegar al
VPS ni publicar APK/AAB automáticamente.

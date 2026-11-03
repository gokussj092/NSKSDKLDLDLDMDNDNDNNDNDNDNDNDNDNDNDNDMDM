# Resultados reales y límites

Estado del método: **PENDING**. Descargas reales de catálogo verificadas: **0**.

| Escenario | Resultado | Interpretación |
| --- | --- | --- |
| GET ficha Play y APKPure | HTML recibido | Metadatos; no prueba de última versión oficial |
| XAPK ARM64 mirror1391 | ZIP íntegro, hash e identidad registrados | Muestra analizada; no redistribuida |
| Inspector compartido XAPK | Falló al identificar base | Recuperación por entrada base explícita |
| Inspector APK base | Correcto | Paquete/versionCode comprobados |
| JADX classes.dex | exit3,22 errores | Parcial; limitación conservada |
| JADX classes2.dex | exit0 | Java estático del actualizador y sobre disponible |
| Configuración incluida | `{}` | Vacía; no hay servidores verificados |
| Respaldo remoto | HTTP404/text/plain/14 bytes | Fallo real; no catálogo |
| Petición principal | Bloqueo auto-review | Sin respuesta autenticada verificada; no se infiere estado del servidor |
| Sobre sintético JCA→Python | Documento completo idéntico | VERIFIED_SYNTHETIC, no VERIFIED_REAL |
| JCA reabre su vector | Bytes idénticos al fixture esperado | Correcto; oráculo sintético independiente |
| Suite unittest | **12/12 correctas** | Clave errónea, tag, truncado, HTML, duplicados y esquema genérico |
| Android/Termux/VPS | No ejecutado | REQUIRES_DEVICE / pendiente de integración |

Comandos efectivos y preparación en [REPRODUCE.md](REPRODUCE.md).
Versiones reales en [DEPENDENCIES.md](DEPENDENCIES.md) y lockfile. No se
certifica el esquema completo de un catálogo Halcon real, ni compatibilidad
de campos internos, versiones previas, exportaciones o métodos de archivo.

Fixtures sanitizados:

- `tests/fixtures/expected.json`: SHA256
  `6cdc0db676fc1526edc2653b5661054a104d652f25496909ea09f272874aeb19`.
- `tests/fixtures/synthetic.envelope`: SHA256
  `e5672b267fcba732610d06e91106b7490fe7960f8d27577aba344ca570ede321`.

Ningún binario de tercero, receta privada, clave, firma autenticadora, perfil
VPN real, credencial ni log de decompilación está incluido en este expediente.
Los datos de referencia son sintéticos y usan example.org.

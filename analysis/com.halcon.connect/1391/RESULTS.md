# Resultado vigente — VERIFIED_REAL, integración de código

| Prueba | Resultado observado |
| --- | --- |
| POST original autorizado | HTTP200, text/plain,645168 bytes |
| Catálogo autenticado | Versión635,101 servidores |
| Java/JCA frente a Python/CLI/worker | JSON completo igual, sin truncar registros |
| CLI con descarga real | Documento completo igual a referencia JCA |
| Pruebas Python |22 correctas:10 proveedor+12 expediente |
| Node focal y regresión de broker/contrato |33 correctas;7 Halcon repetidas tras endurecer validación de secretos |
| Node con bytes reales | Replay correcto de broker+contrato, HTTP simulado |
| Node con red real | REMOTE_NETWORK_DENIED del entorno; VPS pendiente |
| Icono original |192x192/71433 bytes, píxeles idénticos al launcher WebP |
| Catálogo fuente |63,59 fichas; habilitación condicionada a secretos y switches |

SHA256 del sobre real:
`f112a2704421f5b53a82fb859ce925d12f5d8f10280943b8df7597baa49c88f5`.
Referencia JCA80617 bytes (formato original, incluye espacios):
`bd09071797d4c3175216ff958ce180273936ba970394eb4a49bc28d0d056620a`.
La salida CLI usa otra indentación/escape; se comparó el objeto entero.

No se usó un catálogo estático ni sintético para declarar la descarga real.
Los fixtures CI sí son sintéticos y están separados. Se conserva el404 del
respaldo y el primer MAC failure como evidencia histórica. No hay prueba de
producción ni publicación Android. Secretos y JSON reales permanecen fuera de Git.

---

## Registro histórico del primer intento

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

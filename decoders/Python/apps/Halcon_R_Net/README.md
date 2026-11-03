# Halcon R Net / HALCON RAMOS Conectividad

Paquete `com.halcon.connect`, versión4.1.4/build1391. ID estable `halcon-r-net`.
Catálogo remoto real **635 /101 servidores**, HTTP200/645168 bytes cifrados,
completo y autenticado con AES256-GCM. Las15 propiedades de cada registro y
los campos desconocidos se conservan; no se hacen peticiones a los servidores
VPN individuales ni a APIs de VIP, pagos o recompensas.

El actualizador hace POST firmado por timestamp. El fallback de GitHub devuelve
404 y no se usa para simular éxito ni reemplazar la respuesta principal. El
asset/default nativo está vacío. No se identifican ni registran formatos de
archivo/texto o exportación como parte de este proveedor.

La primitiva es símbolos de bloque→bytes Base64→nonce12/ciphertext/tag16;
SHA256(password UTF8)→AES256-GCM sin AAD. La contraseña procede del original
verificado y la huella SHA256 DER mayúscula; no se incrusta en Git ni Android.

## Uso

Proveer en el entorno privado las dos variables del despliegue:

| Variable | Consumidor | Uso |
| --- | --- | --- |
| SPDECODE_HALCON_REQUEST_SECRET | Web/Python CLI | Firma del POST original |
| SPDECODE_HALCON_CATALOG_PASSWORD | Worker Halcon; Web comprueba configuración | Abrir el sobre GCM |

Compose pasa ambas a web y solo la contraseña de contenido al worker; engine.py
la reenvía únicamente al subproceso allowlisted Halcon. No viajan a otros
decodificadores, sesiones de usuario, resultados ni catálogo público.

```bash
python decoders/Python/apps/Halcon_R_Net/server_catalog_decoder.py
python decoders/Python/apps/Halcon_R_Net/server_catalog_decoder.py /ruta/privada/catalog.enc
python decoders/Python/apps/Halcon_R_Net/server_catalog_decoder.py --stdin < /ruta/privada/catalog.enc
```

La salida contiene perfiles privados: redirigirla a un archivo0600 fuera de Git.
Las credenciales faltantes fallan antes de red. No se siguen redirecciones ni se
aceptan URLs del cliente. El broker Node mantiene validación DNS pública y TLS.
Su POST firmado no se reintenta automáticamente.

## Validación y despliegue

[Expediente obligatorio](../../../../analysis/com.halcon.connect/1391/ANALYSIS.md)
con scripts reales, dependencias, revisiones fallidas y evidencia sanitizada.
[Pruebas](TESTING.md). JCA/Python/CLI/worker coinciden en todo el documento real;
el contrato Node pasa con bytes reales y HTTP simulado. El broker Node directo
dio REMOTE_NETWORK_DENIED en el entorno de análisis. **Validación Node en VPS
pendiente**, sin atribuir ese resultado al proveedor.

El código está integrado en la rama de trabajo, condicionado a provisionar
las dos variables. No se ha desplegado, fusionado a main ni publicado Android.
Mantener todos los switches existentes y la versión efectiva monotónica del
catálogo; el mínimo fuente pasa63 y el directorio pasa59 fichas. No reiniciar
el volumen provider-control ni reemplazar otras variables de cloud.env.

# Revisión de consumidores: AustroPlus15, CATNET27 e historial Tunneltweak

Revisión de impacto 2026-11-09. Este expediente consume broker/catálogo/gateway/worker alcanzados mediante imports estáticos; su método criptográfico no se modifica.

Se revisó el diff de server-vpn-provider.mjs: nueva fuente AustroPlus build15; CATNET añade solo un reintento transitorio, conserva preflight/Integrity, fuentes fijas y UUID; Tunneltweak selecciona builds desde historial privado y solo avanza ante426/update_required. pinnedRequest conserva el contrato de200 por defecto y solo el adaptador Tunneltweak acepta426 acotado. Se agrega httpStatus como dato interno de error; los códigos externos permanecen. DNS público anclado, TLS, autenticación, límites y respuestas de las otras aplicaciones se conservan.

server-vpn-catalog.mjs eleva el piso a75 sin reducir overrides del operador. engine.py, c12, c3 y los scripts compartidos de análisis permanecen sin cambios. Los lectores AustroPlus conservan esquema build13/perfiles históricos además del catálogo nuevo; los formatos de otras aplicaciones no se alteran.

Evidencia local:61 pruebas Python y77 Node correctas, más20 del arnés de descargas; npm run build correcto. Las muestras sintéticas/negativas verifican el contrato y no acreditan disponibilidad de otros proveedores. AustroPlus nuevo y recuperación Tunneltweak tienen paridad real completa; Catnet continúa NETWORK_UNAVAILABLE. Expedientes canónicos: analysis/xyz.tekidoer.austroplus.vpn/15, analysis/net.catnet.vpn/27 y analysis/com.tunneltweak.loyalteams/53.

La revisión no concede aprobación automática ni convierte consumidores dinámicos sin resolver en validados. El gate P06 debe mantener su informe de incertidumbre.

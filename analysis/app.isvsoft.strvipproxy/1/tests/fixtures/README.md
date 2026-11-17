# tests/fixtures — STR VIP Proxy

- `synthetic_catalog.json` — catálogo sintético mínimo (meta
  `9.9.9-test`, 1 servidor, 1 tweak). Los valores `enc:` se generaron
  con el propio `encrypt_token` del script operativo sobre valores
  TEST-NET (`198.51.100.1`, `test-payload`): ningún dato real, ninguna
  credencial, ningún host real. SHA-256
  `1506c8350ba665eea1d849c4e32ff5b0bfbcdd3f05f1a5e1a8ab3a61a572620f`.

Un fixture sintético demuestra la lógica implementada (round-trip
`enc:`), NO prueba compatibilidad con una versión real ni conectividad
remota. La evidencia real es la re-corrida en vivo byte por byte
documentada en `RESULTS.md` (el `live.json` completo NO se copia al
expediente: solo su SHA-256 y recuentos).

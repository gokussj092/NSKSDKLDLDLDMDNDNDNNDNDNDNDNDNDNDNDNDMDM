# Herramientas de investigación — GOOD VPN 3.0

- `xxtea_pure.py`: implementación genérica de XXTEA (variante con la
  longitud del texto plano en la última palabra, delta como parámetro,
  sin claves) usada SOLO por los tests de este expediente. No contiene
  claves de formato, endpoints ni datos reales. La criptografía con
  parámetros reales está cubierta por el `--url --summary` del script
  operativo y el `--self-test` del script de archivos (ver RESULTS.md).

Las herramientas de la investigación original (desofuscador `jw1.py`,
decompilación jadx) viven en `~/workspace/catalogs/goodvpn/work/` y
`~/workspace/catalogs/goodvpn/jadx-out/` y se referencian en
MANIFEST.json; no se copian al repo.

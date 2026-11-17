# Herramientas de investigación — MO VPN 1.0.6

- `xxtea_pure.py`: implementación genérica de XXTEA (variante con la
  longitud del texto plano en la última palabra, delta como parámetro,
  sin claves) usada SOLO por los tests de este expediente. No contiene
  claves de formato, endpoints ni datos reales. La criptografía con
  parámetros reales está cubierta por el `--self-test` del script
  operativo (ver RESULTS.md).

Las herramientas de la investigación original (emulación Unicorn de
`libnative-sec.so`, extracción del APK) viven en
`~/workspace/catalogs/movpn/work/` y se referencian en MANIFEST.json;
no se copian al repo (la librería `.so` es binario de terceros y el
arnés depende de rutas locales).

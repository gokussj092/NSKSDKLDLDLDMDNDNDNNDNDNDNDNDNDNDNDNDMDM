# tools/ — M Light

Herramientas propias de este expediente. Contienen SOLO código
genérico sin claves de formato: el códec baybayin (pares de
caracteres = 1 byte) no cifra ni descifra nada por sí solo — la clave
AES vive únicamente en el script operativo
(`decoders/Python/apps/M_Light/M_Light.py`) y nunca se copia aquí.

- `baybayin.py`: codificación baybayin (pares → bytes y bytes →
  pares) con el alfabeto de 17 caracteres del método. Usado por
  `tests/test_method.py` con datos sintéticos y claves de prueba
  propias del test.
- Los scripts de investigación originales (`work/inv1.py`–`work/inv8.py`
  y `ag*.py` del análisis de credenciales) quedan en
  `~/workspace/catalogs/mlight/work/`; no se copian al repo porque
  son material de trabajo con referencias al catálogo vivo.

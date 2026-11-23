# Dependencias observadas

- CPython 3.12.14 y Node.js 24.22.3 en Linux x86_64.
- `requirements.txt` contiene las dependencias del bot y de los lectores.
  `dependencies.lock.txt` registra el entorno de pruebas, con pytest 9.0.2.
- La integración usa pyTelegramBotAPI 4.28.0 para mensajes y respuestas.
  Los lectores reutilizan PyCryptodome, cryptography, Argon2 y MessagePack del proyecto.
- Los instaladores existentes incluyen PHP CLI para los tres formatos PHP.
  PHP CLI no estaba instalado en el entorno local utilizado para esta revisión.
- Python, Node.js, PHP y las dependencias mantienen sus distribuciones
  originales. El cambio no incorpora binarios ni añade dependencias de producción.

Los hashes de distribución de las dependencias transitivas no se registraron
en este entorno. El archivo de versiones permite comparar el entorno observado.

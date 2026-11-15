# Herramientas y dependencias reales

Se reutilizó el entorno aislado existente, sin instalar paquetes nuevos. Python3.12.14/Linux AMD64; Androguard4.1.3 para AXML/certificado (Apache2); JADX1.5.6 completo (Apache2) sobre OpenJDK21.0.13 (GPL2+Classpath); Node24.22.1 (MIT,22 en CI). PyCryptodome3.23.0 (BSD2/componentes dominio público) solo para el lector/oráculos Litron y regresiones.

Todos los54 paquetes instalados se conservan en dependencies.lock.json y requirements.lock.txt, con fuentes/licencias conocidas y versiones. Estar instalado no significa ejecutado: Frida, Capstone, Argon2 y lectores ELF no se utilizaron para estos hallazgos. Licencias desconocidas siguen UNKNOWN_NEEDS_REVIEW, sin aprobación automática. No se distribuyen binarios de terceros.

## Reutilización sin cambios

- scripts/apk_analysis/decompile.py — SHA-256 dd04a05c2cb46bae494af412733d9e27b71167fc86f787371e76dfbddd50a3dd
- analysis/_intake/austro-cat-2026-11-09/tools/decompile.py — SHA-256 c55c999adf38f846ae5e66508b536eefea9b50b481ad1b5a539d968e6308bd77
- analysis/com.tunneldoom.http/432/tools/acquire.py — SHA-256 7d8091243a8097fbaede447706aca4a0bcc03522a347396e20fe6075e5e8864b
- decoders/Python/apps/BD_NET_VPN/codec.py — SHA-256 2517cbeb9adb1aa8aa6f1883f9719b87737e2bdcc722b69af6576d5388b2eed7

El JAR verificado es JADX1.5.6 SHA-256fe3e12c45acf75f92369685fd02d1d7a7323385dc725680a9b98a0dac0ea554b; distribución ZIP545ea2be9c242511bc145755cf4bda2485ade42966e096f8b4d3da2a230e8974, origen https://github.com/skylot/jadx/releases/tag/v1.5.6. No se ejecutan APK/DEX/SO. Las herramientas nuevas permanecen en tools/ o la receta común intake y no se aprueban para el arnés automático.

prepare_catnet.py es la receta propia conservada en analysis/_intake/catnet-play-litron-2026-11-09/tools. compare_builds.py y probe.py son propios por build. Los tests/oráculo JSON del expediente27 se reutilizan sin modificar su mecanismo.

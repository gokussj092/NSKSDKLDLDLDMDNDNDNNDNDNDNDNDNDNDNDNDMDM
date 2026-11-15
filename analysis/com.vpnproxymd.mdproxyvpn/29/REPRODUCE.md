# Reproducir desde la raíz del repositorio

Use una carpeta privada fuera de Git y el Python3.12 con requirements.lock.txt en un entorno aislado revisado; no instalación automática ni aprobación implícita. Los pasos de red deben ejecutarse manualmente. Fuentes/versiones/checksums están en DEPENDENCIES.md y dependencies.lock.json. No publicar cuerpos de catálogo, APK/SO/DEX/JAR ni URLs efímeras del espejo.

```sh
python analysis/_intake/opentunnel-mdproxy-2026-11-09/tools/acquire.py open /ruta/privada/open --build 61
# MD: las rutas APKPure fueron404; conservar ese resultado si se repite.
python analysis/_intake/opentunnel-mdproxy-2026-11-09/tools/acquire_md_mirror.py /ruta/privada/mdproxy
python analysis/_intake/opentunnel-mdproxy-2026-11-09/tools/download_md_mirror.py /ruta/privada/mdproxy
python analysis/_intake/austro-cat-2026-11-09/tools/decompile.py /ruta/privada/mdproxy
python analysis/_intake/opentunnel-mdproxy-2026-11-09/tools/inspect_apk.py mdproxy /ruta/privada/mdproxy
python analysis/_intake/opentunnel-mdproxy-2026-11-09/tools/extract_native.py mdproxy /ruta/privada/mdproxy
python analysis/com.vpnproxymd.mdproxyvpn/29/tools/check_native.py /ruta/privada/mdproxy/libgojni.so
python analysis/com.vpnproxymd.mdproxyvpn/29/tools/probe.py /ruta/privada/mdproxy/catalog.bin
python analysis/com.vpnproxymd.mdproxyvpn/29/tools/verify.py /ruta/privada/mdproxy/catalog.bin --worker
python analysis/com.vpnproxymd.mdproxyvpn/29/tools/verify.py /ruta/privada/mdproxy/embedded.bin
python -m unittest tests.test_md_proxy_vpn tests.test_ultra_tunnel -v
cd cloud/web
node --test tests/opentunnel-mdproxy.test.mjs tests/server-vpn-catalog.test.mjs
npm run build
```

JADX: java -Xmx2200m -XX:ActiveProcessorCount=3 -cp <JAR fijado> jadx.cli.JadxCLI --no-res --decompilation-mode auto -j3. Código3/globalmente parcial esperado; no ocultarlo. Los GET de probe niegan redirecciones y guardan cuerpos privados con modo0600. Repetir exige archivo de salida nuevo. El verificador imprime solo hashes/conteos; no configs. Los oráculos usan Java21 y, para MD, libsodium1.0.18 del host; no cargan SO de Android. Las pruebas normales de Actions son sintéticas/offline; el workflow global de catálogos prueba transporte real sin descifrar.

No se compiló APK ni se desplegó VPS. Hace falta revisión humana para producción y, en OpenTunnel, archivo de teléfono para certificar la vía real de archivo.

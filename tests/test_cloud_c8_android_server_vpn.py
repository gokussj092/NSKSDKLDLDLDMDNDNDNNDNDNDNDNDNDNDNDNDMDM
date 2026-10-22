"""Android Server VPN Phase V source-contract regression checks.

These tests inspect routing, original icons, encrypted cache and safe preview,
without invoking offline decryptors or exposing provider endpoints in the APK.
"""
from __future__ import annotations

import hashlib
import json
import re
import unittest
from pathlib import Path
from xml.etree import ElementTree

ROOT=Path(__file__).resolve().parents[1]
APP=ROOT/"android/app/src/main"
KOTLIN=APP/"java/com/ghostdeveloper/spdecode"
CLOUD=KOTLIN/"cloud"
CPP=APP/"cpp/spdecode_transport.cpp"
WEB=ROOT/"cloud/web"

class PhaseVServerVpnIntegration(unittest.TestCase):
    def test_native_https_only_strict_routes_and_remote_budget(self):
        source=CPP.read_text("utf-8")
        self.assertIn('path == "/api/v1/server-vpn/catalog"',source)
        self.assertIn('path == "/api/v1/server-vpn/icon"',source)
        self.assertIn('path == "/api/v1/server-vpn/decode"',source)
        self.assertIn('path == "/api/v1/decode/import/catalog/remote"',source)
        self.assertIn('kNurCatalogReadTimeoutMs = 165000',source)
        self.assertRegex(source,
            r'path == "/api/v1/decode/import/catalog/remote"\s*\|\|\s*'
            r'path == "/api/v1/server-vpn/decode"')
        self.assertNotIn('setHostnameVerifier',source)
        self.assertNotIn('setSSLSocketFactory',source)

    def test_aes_gcm_no_backup_integrity_and_manual_catalog_retry(self):
        vault=(CLOUD/"ServerVpnSecureCache.kt").read_text("utf-8")
        self.assertIn("noBackupFilesDir",vault)
        self.assertIn('KeyStore.getInstance(store)',vault)
        self.assertIn('setKeySize(256)',vault)
        self.assertIn('GCMParameterSpec(128',vault)
        self.assertIn('cipher.updateAAD(',vault)
        catalog=(CLOUD/"ServerVpnCatalogRepository.kt").read_text("utf-8")
        self.assertIn('versionCheckMillis=15*60_000L',catalog)
        self.assertIn('remote.optBoolean("unchanged",false)',catalog)
        self.assertIn('digest(bytes)!=checksum',catalog)
        self.assertIn('refreshIfDue(force:Boolean=false,announcedVersion:Int=0)',catalog)
        self.assertIn('if(available.isEmpty())0 else previousVersion',catalog)
        self.assertIn('CLOUD_SERVER_VPN_CATALOG_VERSION', (ROOT/"cloud/infra/vps/qa-test.py").read_text("utf-8"))
        activity=(KOTLIN/"MainActivity.kt").read_text("utf-8")
        self.assertIn('if (!BuildConfig.SPDECODE_CLOUD_ENABLED && !supported.hasNativeDecoder)',activity)
        self.assertIn('BuildConfig.SPDECODE_CLOUD_ENABLED -> CloudDecodeClient.MAX_INPUT',activity)
        self.assertIn('cause.code=="NPVS_PROTECTION_UNSUPPORTED"',activity)
        gradle=(ROOT/"android/app/build.gradle.kts").read_text("utf-8")
        self.assertIn('CLIENT_IO_FAILURE',gradle)
        self.assertIn('CLIENT_FORMAT_REJECTED',gradle)
        self.assertIn('remoteVersion<previousVersion',catalog)
        activity=(KOTLIN/"MainActivity.kt").read_text("utf-8")
        self.assertIn('refreshServerVpn(force=true)',activity)
        self.assertIn('serverVpnUnavailable=serverVpnApps.isEmpty()',activity)
        self.assertIn('showCloudLegal',activity)
        ui=(KOTLIN/"SpDecodeApp.kt").read_text("utf-8")
        self.assertIn('R.string.server_vpn_unavailable',ui)
        self.assertIn('R.string.server_vpn_retry',ui)
        self.assertIn('Image(bitmap=app.icon.asImageBitmap()',ui)
        self.assertIn('enabled=!busy && app.decodeEnabled',ui)
        self.assertNotIn('https://ctxrelay.online',ui)
        self.assertNotIn('https://24clanvpn.com',ui)

    def test_all_supported_ui_languages_have_retry_and_consent_strings(self):
        names=("values","values-es","values-ar","values-de","values-fa",
               "values-fr","values-in","values-pt-rBR","values-ru")
        for name in names:
            with self.subTest(locale=name):
                root=ElementTree.parse(APP/"res"/name/"cloud_legal_strings.xml").getroot()
                keys={element.attrib["name"] for element in root.findall("string")}
                self.assertTrue({
                    "server_vpn_unavailable","server_vpn_retry",
                    "cloud_legal_title","cloud_legal_privacy",
                    "cloud_legal_accept_check",
                }<=keys)

    def test_first_use_requires_versioned_encrypted_legal_consent(self):
        code=(CLOUD/"CloudLegalConsent.kt").read_text("utf-8")
        self.assertIn('ServerVpnSecureCache(context).write("legal"',code)
        self.assertIn('record?.optInt("version")==VERSION',code)
        self.assertIn('const val TERMS="https://spdecode.xyz/terms"',code)
        self.assertIn('const val PRIVACY="https://spdecode.xyz/privacy"',code)
        source=(KOTLIN/"MainActivity.kt").read_text("utf-8")
        self.assertIn('CloudLegalConsentDialog(',source)
        self.assertIn('onDecline={finishAffinity()}',source)

    def test_original_icons_are_bitwise_identical_to_app_assets(self):
        originals={
            "nur-tunnel":(
                APP/"res/drawable-nodpi/nur_tunnel_icon.png",
                WEB/"public/server-vpn-icons/nur-tunnel.png"),
            "24clan-green":(
                ROOT/"decoders/Python/apps/24clan_VPN_Green/24clan_VPN_Green.png",
                WEB/"public/server-vpn-icons/24clan-green.png"),
            "hx-tunnel":(
                ROOT/"decoders/Python/apps/HX_Tunnel_VPN/HX_Tunnel_VPN.png",
                WEB/"public/server-vpn-icons/hx-tunnel.png"),
            "mkk-hyper":(
                ROOT/"decoders/Python/apps/MKK_Hyper_VPN/MKK_Hyper_VPN.png",
                WEB/"public/server-vpn-icons/mkk-hyper.png"),
        }
        originals["my-tunnel-proxy"]=(
            ROOT/"decoders/Python/apps/My_Tunnel_Proxy/My_Tunnel_Proxy.png",
            WEB/"public/server-vpn-icons/my-tunnel-proxy.png")
        originals["robust-tunnel"]=(
            ROOT/"decoders/Python/apps/Robust_Tunnel_VPN/Robust_Tunnel_VPN.png",
            WEB/"public/server-vpn-icons/robust-tunnel.png")
        originals["trv-tunnel"]=(
            ROOT/"decoders/Python/apps/TRV_TUNNEL/TRV_TUNNEL.png",
            WEB/"public/server-vpn-icons/trv-tunnel.png")
        originals["4u-tunnel-lite"]=(
            ROOT/"decoders/Python/apps/4U_TUNNEL_LITE/4U_TUNNEL_LITE.png",
            WEB/"public/server-vpn-icons/4u-tunnel-lite.png")
        originals["royal-tunnel"]=(
            ROOT/"decoders/Python/apps/Royal_Tunnel_VPN/Royal_Tunnel_VPN.png",
            WEB/"public/server-vpn-icons/royal-tunnel.png")
        originals["ac-tunnel-vpn"]=(
            ROOT/"decoders/Python/apps/AC_TUNNEL_VPN/AC_TUNNEL_VPN.png",
            WEB/"public/server-vpn-icons/ac-tunnel-vpn.png")
        originals["austroplus-vpn"]=(
            ROOT/"decoders/Python/apps/AustroPlus_VPN/AustroPlus_VPN.png",
            WEB/"public/server-vpn-icons/austroplus-vpn.png")
        originals["http-fenixvpn"]=(
            ROOT/"decoders/Python/apps/HTTP_FenixVPN/HTTP_FenixVPN.png",
            WEB/"public/server-vpn-icons/http-fenixvpn.png")
        originals["http-jireh"]=(
            ROOT/"decoders/Python/apps/HTTP_Jireh/HTTP_Jireh.png",
            WEB/"public/server-vpn-icons/http-jireh.png")
        originals["mx-tunnel-pro"]=(ROOT/"decoders/Python/apps/Mx_Tunnel_PRO/Mx_Tunnel_PRO.png",WEB/"public/server-vpn-icons/mx-tunnel-pro.png")
        originals["megatunnel"]=(ROOT/"decoders/Python/apps/MegaTunnel/MegaTunnel.png",WEB/"public/server-vpn-icons/megatunnel.png")
        originals["http-internet-infinito"]=(ROOT/"decoders/Python/apps/HTTP_Internet_Infinito/HTTP_Internet_Infinito.png",WEB/"public/server-vpn-icons/http-internet-infinito.png")
        originals["freedom-vpn"]=(ROOT/"decoders/Python/apps/FreedomVPN/FreedomVPN.png",WEB/"public/server-vpn-icons/freedom-vpn.png")
        originals["focus-vpn-cloud"]=(ROOT/"decoders/Python/apps/Focus_VPN_Cloud/Focus_VPN_Cloud.png",WEB/"public/server-vpn-icons/focus-vpn-cloud.png")
        originals["eut-vpn"]=(ROOT/"decoders/Python/apps/EUT_VPN/EUT_VPN.png",WEB/"public/server-vpn-icons/eut-vpn.png")
        originals["v2ray-tunnel-plus"]=(ROOT/"decoders/Python/apps/V2ray_Tunnel_Plus/V2ray_Tunnel_Plus.png",WEB/"public/server-vpn-icons/v2ray-tunnel-plus.png")
        originals["tunelguard-vpn"]=(ROOT/"decoders/Python/apps/TunelGuard_VPN/TunelGuard_VPN.png",WEB/"public/server-vpn-icons/tunelguard-vpn.png")
        originals["http-wakko"]=(ROOT/"decoders/Python/apps/HTTP_Wakko/HTTP_Wakko.png",WEB/"public/server-vpn-icons/http-wakko.png")
        originals["http-socketclay"]=(ROOT/"decoders/Python/apps/HTTP_SocketClay/HTTP_SocketClay.png",WEB/"public/server-vpn-icons/http-socketclay.png")
        originals["tunneltweak"]=(ROOT/"decoders/Python/apps/Tunneltweak/Tunneltweak.png",WEB/"public/server-vpn-icons/tunneltweak.png")
        for app_id,(original,served) in originals.items():
            with self.subTest(app=app_id):
                self.assertTrue(original.is_file(),original)
                self.assertTrue(served.is_file(),served)
                raw=served.read_bytes()
                self.assertGreater(len(raw),32)
                self.assertEqual(raw[:8],b"\x89PNG\r\n\x1a\n")
                self.assertEqual(hashlib.sha256(original.read_bytes()).digest(),
                                 hashlib.sha256(raw).digest())

    def test_generated_cloud_preview_protects_other_providers(self):
        source=(ROOT/"android/app/build.gradle.kts").read_text("utf-8")
        self.assertIn('entry.extension=="nurservers" || entry.extension=="vpnservers"',source)
        self.assertIn('updateResultBlock("    private fun decodeServerVpnProvider(id:String) {"',source)
        self.assertIn('presentDecodedRecord(',source)
        self.assertIn('CloudLargeResultNotice(',source)
        client=(CLOUD/"CloudDecodeClient.kt").read_text("utf-8")
        self.assertIn('suspend fun decodeServerVpnProvider(id:String)',client)
        self.assertIn('JSONObject().put("id",id).put("consent",true)',client)

if __name__=="__main__":
    unittest.main()

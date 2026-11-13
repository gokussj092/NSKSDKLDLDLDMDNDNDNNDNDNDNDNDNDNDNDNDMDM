"""Contract checks for SSH-only catalogs, safe Play Store link and 14 locales."""
from pathlib import Path
import unittest
import xml.etree.ElementTree as ET

ROOT=Path(__file__).resolve().parents[1]
def source(path):
    return (ROOT/path).read_text(encoding="utf-8")

class SshCatalogUiContract(unittest.TestCase):
    def test_category_filters(self):
        directory=source("android/app/src/main/java/com/ghostdeveloper/spdecode/ServerVpnDirectory.kt")
        for token in ('"opentunnel-ssh"', '"speigo-vpn-ssh"',
                      'ServerVpnListFilter.ALL->!isSsh',
                      'ServerVpnListFilter.ENABLED->!isSsh && app.decodeEnabled',
                      'ServerVpnListFilter.FAVORITES->!isSsh && app.id in favorites',
                      'ServerVpnListFilter.SSH_ACCOUNTS->isSsh'):
            self.assertIn(token,directory)

    def test_clickable_hex_tunnel_url_is_allowlisted(self):
        directory=source("android/app/src/main/java/com/ghostdeveloper/spdecode/ServerVpnDirectory.kt")
        ui=source("android/app/src/main/java/com/ghostdeveloper/spdecode/SpDecodeApp.kt")
        activity=source("android/app/src/main/java/com/ghostdeveloper/spdecode/MainActivity.kt")
        self.assertIn("https://play.google.com/store/apps/details?id=com.hex.tunnel.jotchuast",directory)
        self.assertIn('            HEX_TUNNEL_PLAY_URL,',activity)
        self.assertIn('onExternalLink(HEX_TUNNEL_PLAY_URL)',ui)
        self.assertIn('testTag("server_vpn_ssh_accounts_tab")',ui)
        self.assertIn('testTag("server_vpn_ssh_hex_tunnel")',ui)

    def test_rounded_search_fields(self):
        ui=source("android/app/src/main/java/com/ghostdeveloper/spdecode/SpDecodeApp.kt")
        vpn=ui[ui.index("private fun ServerVpnScreen("):]
        result=source("android/app/src/main/java/com/ghostdeveloper/spdecode/LargeResultViewer.kt")
        self.assertIn('shape=RoundedCornerShape(30.dp)',vpn)
        self.assertIn('shape=RoundedCornerShape(30.dp)',result)

    def test_locales_have_exactly_the_three_strings(self):
        locales=("values", "values-es", "values-pt-rBR", "values-fr", "values-de", "values-it", "values-tr", "values-ru", "values-ar", "values-fa", "values-hi", "values-ja", "values-in", "values-vi")
        expected={"server_vpn_filter_ssh_accounts","server_vpn_ssh_notice_text","server_vpn_ssh_no_matches"}
        for locale in locales:
            path=ROOT/"android/app/src/main/res"/locale/"ssh_accounts_strings.xml"
            entries={e.attrib["name"]:e.text for e in ET.parse(path).getroot().findall("string")}
            self.assertEqual(set(entries),expected,locale)
            self.assertTrue(all(entries.values()),locale)

if __name__=="__main__":
    unittest.main()

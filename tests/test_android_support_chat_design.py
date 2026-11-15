"""SP-DECODE native support chat owns one toolbar; ad-sellers are factual."""
import unittest
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
def content(path):
    return (ROOT/path).read_text(encoding="utf-8")

class AndroidSupportChatDesignTests(unittest.TestCase):
    def test_support_header_is_not_nested_in_generic_account_header(self):
        parent=content("android/app/src/main/java/com/ghostdeveloper/spdecode/NativeCommerceScreens.kt")
        chat=content("android/app/src/main/java/com/ghostdeveloper/spdecode/CommerceSupportPage.kt")
        self.assertIn('val supportOwnHeader=page in setOf("support","report")',parent)
        self.assertIn('if(!supportOwnHeader){',parent)
        self.assertIn('if(supportOwnHeader)',parent)
        self.assertIn('onExit={back()}',parent)
        self.assertIn('BackHandler(enabled=active!=null||creating){navigateBack()}',chat)
        self.assertIn('active!=null->{activeId="";text="";creating=false;error=null}',chat)
        self.assertIn('IconButton(onClick=onExit',chat)
        self.assertIn('onExit:()->Unit',chat)

    def test_design_updates_preserve_messages_and_send_semantics(self):
        chat=content("android/app/src/main/java/com/ghostdeveloper/spdecode/CommerceSupportPage.kt")
        for required in ['chatHeader=Color(0xFF0B1923)',
            'chatOutgoing=Color(0xFF123B4B)',
            'chatIncoming=Color(0xFF1C2934)',
            'RoundedCornerShape(topStart=20.dp',
            'auth.sendSupportMessage(activeId,text.trim())',
            'auth.supportInbox()','"Conversation closed"',
            '"You can still read earlier messages."',
            'CommerceI18n.translate(language']:
            self.assertIn(required,chat)

    def test_admob_authorized_seller_is_additive_to_unity_list(self):
        sellers=content("cloud/web/public/app-ads.txt").splitlines()
        self.assertEqual(sellers.count("google.com, pub-6771239583897519, DIRECT, f08c47fec0942fa0"),1)
        self.assertIn("unity.com, 162529223, DIRECT, 96cabb5fbdde37a7",sellers)
        self.assertGreater(len(sellers),160)

if __name__=="__main__":
    unittest.main()

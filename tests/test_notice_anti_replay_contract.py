"""Regression guard for notification anti-spam controls in Node and Android."""
from pathlib import Path
import unittest
ROOT=Path(__file__).resolve().parents[1]
class TestNoticeAntiReplay(unittest.TestCase):
 def test_android_requires_subscription_cutoff_and_limits_batch(self):
  source=(ROOT/'android/app/src/main/java/com/ghostdeveloper/spdecode/cloud/CloudNotifications.kt').read_text()
  for value in ('eligible_since_server','opt_in_at_wall','serverTime',
                'NoticeSubscriptionPolicy.cutoff','MAX_ALERTS_PER_SYNC=3',
                'delivery !in setOf("push","poll")'):
   self.assertIn(value,source)
  self.assertNotIn('val now=System.currentTimeMillis()\n        for(i in 0 until list.length())',source)
 def test_admin_category_delivery_and_api_time(self):
  frontend=(ROOT/'cloud/web/app/admin/admin-notifications.jsx').read_text()
  api=(ROOT/'cloud/web/lib/app-notifications.mjs').read_text()
  for label in ('Tipo de notificación','Urgencia','Método de entrega','Caducidad'):
   self.assertIn(label,frontend)
  self.assertIn("serverTime:Date.now()",api)
  self.assertIn("if(notice.delivery!=='poll')",api)
  self.assertIn('NOTICE_TYPES.includes(input.type)',api)
 def test_no_new_public_endpoint_or_secrets(self):
  android=(ROOT/'android/app/src/main/java/com/ghostdeveloper/spdecode/cloud/CloudNotifications.kt').read_text()
  self.assertNotIn('CLOUD_NOTICE_FCM_SERVICE_ACCOUNT_JSON',android)
  self.assertNotIn('https://fcm.googleapis.com',android)
if __name__=='__main__':unittest.main()

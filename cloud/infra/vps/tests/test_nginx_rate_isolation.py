"""Contract: ordinary API metadata never contributes to Nginx decoder limits."""
import runpy
import unittest
from pathlib import Path

GEN = Path(__file__).resolve().parents[1] / "nginx-config.py"

class NginxRateIsolation(unittest.TestCase):
    def test_generated_proxy_isolates_decode_from_info(self):
        result = runpy.run_path(str(GEN))["generate"](
            "spdecode.xyz", "api.spdecode.xyz", "panel.spdecode.xyz", False
        )
        self.assertIn('map "$uri:$http_x_sp_operation" $spdecode_expensive_key {', result)
        self.assertIn('default "";', result)
        self.assertIn(
            'limit_req_zone $spdecode_expensive_key zone=spdecode_v2_edge:10m rate=10r/s;',
            result,
        )
        self.assertNotIn(
            "limit_req_zone $binary_remote_addr zone=spdecode_v2_edge", result
        )
        expensive = result.split(
            'map "$uri:$http_x_sp_operation" $spdecode_expensive_key {', 1
        )[1].split("}", 1)[0]
        self.assertIn("(4|5|6|7|8|9|12)", expensive)
        self.assertNotIn("transport:13", expensive)
        self.assertNotIn("transport:20", expensive)
        self.assertNotIn("transport:24", expensive)
        self.assertIn("proxy_set_header X-Real-IP $remote_addr;", result)
        self.assertIn("limit_conn spdecode_uploads 12;", result)

if __name__ == "__main__":
    unittest.main()

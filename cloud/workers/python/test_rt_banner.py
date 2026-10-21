"""REESE .rt bannerImage removal, including nested and variable images."""
import importlib.util
import json
import unittest
from pathlib import Path

SRC=Path(__file__).resolve().parents[3]/"decoders/Python/apps/REESE_TUNNEL/reese_tunnel.py"
spec=importlib.util.spec_from_file_location("reese_tunnel_banner_test",SRC)
reese=importlib.util.module_from_spec(spec)
spec.loader.exec_module(reese)


class RtBannerImageTests(unittest.TestCase):
    def test_removes_nested_images_but_preserves_other_fields(self):
        for image in ("/9j/4AAQSkZJRgABAQ...", "differentBase64", "", {"nested":"value"}):
            document={"meta":{"bannerImage":image,"version":"5"},
                      "config":{"profileName":"test","sshHost":"server.example",
                                "bannerImage":image,
                                "list":[{"bannerImage":image,"port":443}],
                                "displayImage":"keep-this"}}
            result=reese.decode(json.dumps(document).encode("utf-8"))
            self.assertEqual(result["config"]["profileName"],"test")
            self.assertEqual(result["config"]["sshHost"],"server.example")
            self.assertEqual(result["config"]["list"][0]["port"],443)
            self.assertEqual(result["config"]["displayImage"],"keep-this")
            self.assertEqual(result["meta"]["version"],"5")
            self.assertNotIn("bannerImage",json.dumps(result))
            self.assertNotIn("bannerImage",reese.run(json.dumps(document).encode()))

    def test_exact_name_only(self):
        obj={"profileName":"test","sshHost":"host","bannerImage":"large",
             "BannerImage":"unchanged","bannerImageUrl":"unchanged"}
        result=reese.decode(json.dumps(obj).encode())
        self.assertEqual(result["BannerImage"],"unchanged")
        self.assertEqual(result["bannerImageUrl"],"unchanged")
        self.assertNotIn("bannerImage",result)


if __name__=="__main__":
    unittest.main()

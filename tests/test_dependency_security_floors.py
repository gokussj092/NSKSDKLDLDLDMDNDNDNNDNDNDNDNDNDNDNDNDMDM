"""Known high-impact advisory floors. No network, lockfile, or third-party deps.

This guards direct source manifests only. npm audit, pip-audit and the
authenticated GitHub Dependabot alert inbox are separate verification gates.
"""
import json
import pathlib
import re
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]


def version(value):
    if not re.fullmatch(r"[0-9]+(?:\.[0-9]+){2}", value):
        raise AssertionError(f"Dependency must be pinned to an exact 3-part release: {value!r}")
    return tuple(map(int, value.split(".")))


class KnownVulnerabilityFloors(unittest.TestCase):
    def test_next_and_react_security_releases(self):
        for file in ("website/package.json", "cloud/web/package.json"):
            with self.subTest(manifest=file):
                deps = json.loads((ROOT / file).read_text(encoding="utf-8"))["dependencies"]
                self.assertGreaterEqual(version(deps["next"]), (16, 4, 1),
                    "Next.js GHSA-673q-mjm6-r5xr / GHSA-2464-fhr4-w9xw")
                self.assertGreaterEqual(version(deps["react"]), (19, 3, 1),
                    "React Server Components GHSA-xqc2-xf4c-x3h3")
                self.assertGreaterEqual(version(deps["react-dom"]), (19, 3, 1))
                self.assertEqual(deps["react"], deps["react-dom"])

    def test_msgpack_memory_and_denial_of_service_fixes(self):
        for file in ("requirements.txt",
                     "temporary/original-app-config-export/scripts/requirements-dark-lab.txt"):
            with self.subTest(manifest=file):
                text = (ROOT / file).read_text(encoding="utf-8")
                matches = re.findall(r"(?m)^msgpack==([^\s#]+)", text)
                self.assertEqual(len(matches), 1)
                self.assertGreaterEqual(version(matches[0]), (1, 2, 4),
                    "msgpack GHSA-j586-36cw-2gc2 and subsequent 1.2.4 hardening")


if __name__ == "__main__":
    unittest.main()

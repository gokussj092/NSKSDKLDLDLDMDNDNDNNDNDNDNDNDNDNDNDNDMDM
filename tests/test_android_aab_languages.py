"""AAB language bundle regression: do not depend on Google Play locale downloads."""
from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from zipfile import ZipFile

from scripts.ci.verify_aab_locales import check_aab, check_bundle_config, check_sources


def _var(value: int) -> bytes:
    out = bytearray()
    while value > 127:
        out.append((value & 127) | 128)
        value >>= 7
    out.append(value)
    return bytes(out)


def _num(field: int, value: int) -> bytes:
    return _var(field * 8) + _var(value)


def _msg(field: int, body: bytes) -> bytes:
    return _var(field * 8 + 2) + _var(len(body)) + body


def _config(*, negate: bool, language: bool = True) -> bytes:
    # official bundletool config.proto: value LANGUAGE=3 and negate=true
    dim = _num(1, 3 if language else 2)
    if negate:
        dim += _num(2, 1)
    return _msg(2, _msg(1, _msg(1, dim)))


class AndroidAabLanguagesTests(unittest.TestCase):
    def test_picker_locale_registry_matches_all_packaged_translations(self):
        supported = check_sources()
        self.assertEqual(
            set(supported),
            {"en", "es", "pt-BR", "ar", "fa", "fr", "id", "ru",
             "de", "tr", "vi", "hi", "ja", "it"},
        )

    def test_config_rejects_play_language_splits(self):
        check_bundle_config(_config(negate=True))
        with self.assertRaisesRegex(ValueError, "LANGUAGE splits"):
            check_bundle_config(_config(negate=False))
        with self.assertRaisesRegex(ValueError, "LANGUAGE splits"):
            check_bundle_config(_config(negate=True, language=False))

    def test_config_rejects_missing_truncated_and_ambiguous_metadata(self):
        for data in (b"", b"\\x12", _msg(2, b""), _msg(2, _msg(1, b""))):
            with self.subTest(data=data):
                with self.assertRaises(ValueError):
                    check_bundle_config(data)
        with self.assertRaisesRegex(ValueError, "LANGUAGE splits"):
            check_bundle_config(_msg(2, _msg(1, _msg(1, _num(1, 3) + _num(2, 1) + _num(2, 0)))))

    def test_complete_aab_metadata_is_required(self):
        with tempfile.TemporaryDirectory() as folder:
            aab = Path(folder) / "test.aab"
            with ZipFile(aab, "w") as z:
                z.writestr("BundleConfig.pb", _config(negate=True))
                z.writestr("base/resources.pb", b"compiled resources placeholder")
            check_aab(aab)
            with ZipFile(aab, "w") as z:
                z.writestr("BundleConfig.pb", _config(negate=True))
            with self.assertRaisesRegex(ValueError, "resources.pb"):
                check_aab(aab)


if __name__ == "__main__":
    unittest.main()

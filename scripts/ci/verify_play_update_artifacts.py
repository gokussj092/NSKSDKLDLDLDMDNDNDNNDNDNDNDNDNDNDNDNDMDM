#!/usr/bin/env python3
"""Assert Play In-App Updates ships ONLY inside the Play AAB."""
from pathlib import Path
from zipfile import ZipFile
import sys

MARKER = "spdecode-play-updates-enabled.marker"

def verify(apk_path, aab_path):
    with ZipFile(apk_path) as apk, ZipFile(aab_path) as aab:
        apk_files = set(apk.namelist())
        aab_files = set(aab.namelist())
        assert "assets/" + MARKER not in apk_files, "Telegram APK contains Play marker"
        assert "base/assets/" + MARKER in aab_files, "Play AAB missing Play marker"
        assert aab.read("base/assets/" + MARKER).strip() == b"PLAY_AAB_ONLY"
        assert any(n.startswith("base/dex/") and n.endswith(".dex") for n in aab_files), "AAB dex missing"
        assert any(n.startswith("classes") and n.endswith(".dex") for n in apk_files), "APK dex missing"
    print("PASS: Play updater packaged in AAB only; external Telegram APK isolated")

if __name__ == "__main__":
    if len(sys.argv) != 3:
        raise SystemExit("Usage: verify_play_update_artifacts.py signed.apk signed.aab")
    verify(Path(sys.argv[1]), Path(sys.argv[2]))

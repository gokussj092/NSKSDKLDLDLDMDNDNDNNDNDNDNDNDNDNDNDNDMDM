#!/usr/bin/env python3
"""Pinned, isolated Android software-emulator probe; never fabricates keys.

--prepare downloads the official SDK archives with fixed SHA-256 checksums.
Otherwise a bounded emulator and an interactive JSON-lines controller run in
one network namespace. Child commands receive DEVNULL stdin so ADB cannot
consume subsequent controller requests. APKs, AVD state and logs stay in work/.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import threading
import time
import urllib.request
import zipfile

ARCHIVES = (
    ("emulator-linux_x64-16428233.zip", "https://dl.google.com/android/repository/", 349654171,
     "b08fc43d8608d2955f607f1b287beb525041e730086bdca3af152accac3af9c1", ""),
    ("platform-tools_r37.0.1-linux.zip", "https://dl.google.com/android/repository/", 9054187,
     "d230f13842f60f782a8645f9c813f8f845bf36089ea7289f28c48f17979313f1", ""),
    ("x86_64-30_r16.zip", "https://dl.google.com/android/repository/sys-img/google_apis/", 1438186618,
     "daae27654be74ae83a484daea4db2c0c77b4f4ad661a645bd5f36d96ce03e4d5", "system-images/android-30/google_apis"),
)


def digest(path):
    h = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024): h.update(chunk)
    return h.hexdigest()


def prepare(base):
    for name, origin, size, expected, subdir in ARCHIVES:
        archive = base / name
        if not archive.exists() or archive.stat().st_size != size:
            temporary = archive.with_suffix(".part")
            count, last = 0, time.monotonic()
            with urllib.request.urlopen(origin + name, timeout=30) as response, temporary.open("wb") as output:
                while chunk := response.read(1024 * 1024):
                    output.write(chunk); count += len(chunk)
                    if time.monotonic() - last > 10:
                        print(json.dumps({"archive": name, "downloadedMiB": count // 2**20}), flush=True)
                        last = time.monotonic()
            if count != size: raise ValueError("Incomplete SDK archive")
            temporary.replace(archive)
        if digest(archive) != expected: raise ValueError("SDK SHA-256 mismatch: " + name)
        destination = base / "sdk" / subdir
        destination.mkdir(parents=True, exist_ok=True)
        with zipfile.ZipFile(archive) as zipped:
            for entry in zipped.infolist():
                target = destination / entry.filename
                if not target.resolve().is_relative_to(destination.resolve()):
                    raise ValueError("Unsafe SDK archive path")
                zipped.extract(entry, destination)
                mode = entry.external_attr >> 16
                if mode and target.is_file(): target.chmod(mode & 0o777)
        print(json.dumps({"archive": name, "verifiedAndExtracted": True}), flush=True)


def run(base, seconds):
    name = "FlexB46_Software"
    avds = base / "avd"
    avd = avds / (name + ".avd")
    avd.mkdir(parents=True, exist_ok=True)
    (avds / (name + ".ini")).write_text("avd.ini.encoding=UTF-8\npath=" + str(avd) + "\ntarget=android-30\n")
    config = {"AvdId": name, "abi.type": "x86_64", "hw.cpu.arch": "x86_64", "hw.cpu.ncore": "2",
              "hw.ramSize": "2048", "hw.lcd.width": "720", "hw.lcd.height": "1280", "hw.lcd.density": "320",
              "hw.gpu.enabled": "yes", "hw.gpu.mode": "swiftshader", "image.sysdir.1": "system-images/android-30/google_apis/x86_64/",
              "tag.id": "google_apis", "target": "android-30", "disk.dataPartition.size": "2048M",
              "hw.keyboard": "yes", "hw.camera.back": "none", "hw.camera.front": "none"}
    (avd / "config.ini").write_text("".join(k + "=" + v + "\n" for k, v in config.items()))
    sdk = base / "sdk"
    env = {**os.environ, "ANDROID_SDK_ROOT": str(sdk), "ANDROID_AVD_HOME": str(avds)}
    adb = str(sdk / "platform-tools/adb")
    args = [str(sdk / "emulator/emulator"), "-avd", name, "-no-window", "-no-audio", "-no-boot-anim",
            "-no-snapshot", "-show-kernel", "-gpu", "swiftshader", "-accel", "off", "-cores", "2", "-memory", "2048",
            "-camera-back", "none", "-camera-front", "none", "-netspeed", "full", "-netdelay", "none", "-port", "5554"]
    jobs = []
    with (base / "emulator.log").open("wb") as log, (base / "controller.jsonl").open("a") as audit:
        audit_path = base / "controller.jsonl"
        audit_path.chmod(0o600)
        process = subprocess.Popen(args, env=env, stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT)
        def emit(result):
            audit.write(json.dumps(result) + "\n"); audit.flush()
            print(json.dumps(result), flush=True)
        def stop_guest():
            if process.poll() is None: process.terminate()
        timer = threading.Timer(seconds, stop_guest); timer.daemon = True; timer.start()
        emit({"controllerReady": True, "emulatorPid": process.pid, "runtimeLimitSeconds": seconds})
        try:
            for line in sys.stdin:
                try:
                    q = json.loads(line)
                    if q.get("exit"): break
                    if q.get("status"):
                        emit({"emulatorExitCode": process.poll(), "jobs": [p.poll() for p in jobs]}); continue
                    if "stop" in q:
                        p = jobs[q["stop"]]
                        if p.poll() is None: p.terminate()
                        emit({"stoppedJob": q["stop"]}); continue
                    command = q.get("host") or [adb, "-s", "emulator-5554"] + q["adb"]
                    if q.get("spawn"):
                        path = Path(q["save_stdout"])
                        with path.open("xb") as output:
                            path.chmod(0o600)
                            p = subprocess.Popen(command, env=env, stdin=subprocess.DEVNULL, stdout=output, stderr=subprocess.STDOUT)
                        jobs.append(p); emit({"job": len(jobs) - 1, "pid": p.pid}); continue
                    r = subprocess.run(command, env=env, stdin=subprocess.DEVNULL, capture_output=True, timeout=min(q.get("timeout", 30), 180))
                    result = {"exitCode": r.returncode}
                    if q.get("save_stdout"):
                        path = Path(q["save_stdout"]); path.write_bytes(r.stdout); path.chmod(0o600)
                        result["savedBytes"] = len(r.stdout)
                    else: result["stdout"] = r.stdout.decode("utf-8", errors="replace")[:12000]
                    result["stderr"] = r.stderr.decode("utf-8", errors="replace")[:2000]
                    emit(result)
                except Exception as error:
                    emit({"controllerError": type(error).__name__, "message": str(error)[:300]})
        finally:
            timer.cancel()
            for p in jobs:
                if p.poll() is None: p.terminate()
            stop_guest()
            try: process.wait(timeout=15)
            except subprocess.TimeoutExpired: process.kill(); process.wait()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--work", type=Path, default=Path(__file__).resolve().parent / "work/flex-b46-avd")
    parser.add_argument("--prepare", action="store_true")
    parser.add_argument("--seconds", type=int, default=1200)
    args = parser.parse_args()
    base = args.work.resolve(); base.mkdir(parents=True, exist_ok=True)
    if not 60 <= args.seconds <= 1800: parser.error("Runtime must be 60..1800 seconds")
    if args.prepare: prepare(base)
    else: run(base, args.seconds)


if __name__ == "__main__": main()

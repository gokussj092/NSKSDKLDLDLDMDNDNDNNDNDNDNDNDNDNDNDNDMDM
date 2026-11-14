#!/usr/bin/env python3
"""Reproduce the fixed integration inventory without executing vendor modules.

The input is the owner's five supplied batches. Never infer public catalogs
from arbitrary URLs or treat generic subscriptions as a vendor server list.
"""
import ast
import json
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[5]
OUT = ROOT / "cloud/web/content/supplied-integrations.json"
BASE = "9f20db3"
SUPPLIED = "361e73c"


def constants(path):
    result = {}
    def value(node):
        if isinstance(node, ast.Name):
            return result[node.id]
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            return value(node.left) + value(node.right)
        return ast.literal_eval(node)
    for node in ast.parse(path.read_text()).body:
        if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
            try:
                result[node.targets[0].id] = value(node.value)
            except (KeyError, ValueError, TypeError):
                pass
    return result


def build():
    paths = subprocess.check_output(["git", "diff", "--name-only", BASE, SUPPLIED,
                                     "--", "decoders/Python/apps"], cwd=ROOT).decode().splitlines()
    apps = sorted({p.split("/")[3] for p in paths if len(p.split("/")) > 4})
    assert len(apps) == 57
    items = []
    no_catalog = {"Hex_Custom": "FILE_ONLY", "OneFTunnel": "USER_PROFILES_ONLY",
                  "V2Box": "USER_SUBSCRIPTIONS_ONLY", "SNI_Tunnel": "USER_SUBSCRIPTIONS_ONLY",
                  "XtraVPN": "CUSTOM_CODE_URL_REQUIRED", "IGNIX_VPN_MAX": "CIPHER_PENDING",
                  "XJ_VPN": "PLAY_INTEGRITY_REQUIRED", "YLA_VPN": "PROVIDER_SIGNATURE_REQUIRED",
                  "VertexSnipher": "PROVIDER_IDENTITY_REQUIRED"}
    for app in apps:
        folder = ROOT / "decoders/Python/apps" / app
        manifest = json.loads((folder / "manifest.json").read_text())
        catalog = manifest.get("catalog") or {}
        script = catalog.get("entrypoint") or manifest.get("entrypoint")
        if app == "CATNET_VPN":
            script = "server_catalog_decoder.py"
        assert script and (folder / script).is_file(), app
        values = constants(folder / script)
        item = {"id": manifest["id"], "appDir": app, "name": manifest["name"],
                "package": manifest.get("package") or manifest.get("packageName"), "versionCode": manifest.get("versionCode"),
                "versionName": manifest.get("versionName"), "catalogModule": script,
                "extensions": manifest.get("extensions", []),
                "textPrefixes": manifest.get("textPrefixes", []),
                "fileModule": manifest.get("fileDecoder"), "requests": []}
        if app == "HX_Tunnel_VPN":
            item["id"] = "hx-tunnel"  # Preserve existing Android favorites and operator switches.
        if not item["fileModule"]:
            candidates = sorted(folder.glob("*_archivos.py"))
            if candidates:
                assert len(candidates) == 1, app
                item["fileModule"] = candidates[0].name
        icons = sorted(folder.glob("*.png"))
        item["sourceIcon"] = icons[0].name if icons else None
        item["icon"] = item["id"] + ".png"
        if app == "HX_Tunnel_VPN":
            item["icon"] = "hx-tunnel.png"
        item["catalogState"] = no_catalog.get(app, "CONNECTED")
        if app == "CATNET_VPN":
            item["existingBroker"] = True  # Preserve its existing Firebase/preflight protocol.
        elif app not in no_catalog:
            url = next((values[k] for k in ("CATALOG_URL", "CONFIGS_URL", "APP_CONFIG_URL", "API_URL", "UPDATER_URL")
                        if isinstance(values.get(k), str)), None)
            assert url, app
            agent = values.get("USER_AGENT", "Dalvik/2.1.0")
            if app == "DocNet_VPN":
                agent = "Dart/3.4 (dart:io)"
            if app == "LinkLayer":
                agent = "Go-http-client/1.1"
            if app == "Litron_VPN":
                agent = "okhttp/5.0.0-alpha.3"
            request = {"name": "servers", "url": url, "agent": agent, "method": "GET", "headers": {}}
            if app in {"AT_NET_VPN", "JetRoi", "Marvs_SSH", "MM_Tunnel", "REG_Tunnel_VPN", "RNV_Tunnel_VPN", "Shield_Tunnel"}:
                request.update(method="POST", body=values["FORM_BODY"].decode("ascii"), headers={"Content-Type": "application/x-www-form-urlencoded"})
            if app == "DTunnel_Mod":
                request["headers"] = {"dtunnel-update": "app_config"}
                request["secretHeader"] = {"header": "dtunnel-token", "env": "SPDECODE_DTUNNEL_REQUEST_ID"}
            if app == "IP_Tunnel":
                request["headers"] = {"X-App-Id": values["APP_ID"], "X-App-Version": values["APP_VERSION"], "X-App-Auth-Mode": "session_v2"}
                request["sessionHeaders"] = True
            if app == "SLOW_DNS":
                request["name"] = "updater"
                item["requests"].append(request)
                request = {"name": "servers", "url": "https://raw.githubusercontent.com/MinaDiNabil/update.link/refs/heads/main/slowdns_config.json", "agent": agent, "method": "GET", "headers": {}}
            if app == "PNT_VPN":
                request["name"] = "updater"
                item["requests"].append(request)
                request = {"name": "servers", "url": "https://raw.githubusercontent.com/sansoe2022/new_pntvpn/refs/heads/main/v28Config", "agent": agent, "method": "GET", "headers": {}}
            item["requests"].append(request)
            if app == "EDOZ_Tunnel_Pro":
                item["requests"].append({**request, "name": "vip", "url": values["VIP_CATALOG_URL"]})
            if app == "SN_VPN":
                item["requests"].append({**request, "name": "v2", "url": values["CATALOG_V2_URL"]})
        # Keep public metadata separate from these backend-only source descriptors.
        items.append(item)
    OUT.write_text(json.dumps({"schemaVersion": 1, "sourceCommit": SUPPLIED, "apps": items}, ensure_ascii=False, indent=2) + "\n")
    print("Supplied integration inventory: 57 apps")


if __name__ == "__main__":
    build()

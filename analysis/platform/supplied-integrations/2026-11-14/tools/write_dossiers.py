#!/usr/bin/env python3
"""Reconcile canonical package/build integration records, preserving old proof.

This is a connection review, not a claim of new cryptographic or live proof.
"""
import hashlib
import json
from pathlib import Path

ROOT=Path(__file__).resolve().parents[5]
CENTRAL=Path("analysis/platform/supplied-integrations/2026-11-14")
SHARED=["cloud/web/lib/server-vpn-catalog.mjs","cloud/web/lib/server-vpn-provider.mjs",
        "cloud/web/lib/server-vpn-gateway.mjs","cloud/workers/python/catalog_vpn_bridge.py",
        "cloud/workers/python/supplied_bridge.py","cloud/web/lib/supplied-integrations.mjs"]


def main():
    items=json.loads((ROOT/"cloud/web/content/supplied-integrations.json").read_text())["apps"]
    for item in items:
        folder=ROOT/"analysis"/item["package"]/str(item["versionCode"])
        folder.mkdir(parents=True,exist_ok=True)
        manifest=folder/"MANIFEST.json"
        code="decoders/Python/apps/"+item["appDir"]+"/"+item["catalogModule"]
        if manifest.exists():
            value=json.loads(manifest.read_text())
            paths=value.get("code_paths",[])
            if isinstance(paths,dict):paths=[p for p in paths.values() if isinstance(p,str)]
            value["code_paths"]=sorted(set(paths+SHARED))
            value["integration_review"]={"scope":"Connection only; existing algorithm evidence/status preserved.",
                                         "record":str(CENTRAL/"MANIFEST.json"),"status":"PARTIAL"}
        else:
            value={"schema_version":1,"package_name":item["package"],"version_code":item["versionCode"],
                   "app_name":item["name"],"version_name":item["versionName"],"status":"PARTIAL",
                   "authorization_note":"Owner requested connection of supplied methods; no credentials or attestations invented.",
                   "targets":[{"kind":"catalog","status":item["catalogState"]},
                              {"kind":"files","extensions":item["extensions"]},
                              {"kind":"text","prefixes":item["textPrefixes"]}],
                   "inputs":[{"path":code,"sha256":hashlib.sha256((ROOT/code).read_bytes()).hexdigest()}],
                   "tooling":[{"path":str(CENTRAL/"tools/verify_provider.py"),"provider":item["id"]}],
                   "dependencies":[{"lockfile":"requirements.txt"},{"lockfile":"cloud/web/package-lock.json"}],
                   "code_paths":SHARED+[code],
                   "connection_authentication":{"status":"UNCONFIRMED","scope":"Connection review only"}}
        manifest.write_text(json.dumps(value,ensure_ascii=False,indent=2)+"\n")
        for filename in ("ANALYSIS.md","REPRODUCE.md","RESULTS.md","DEPENDENCIES.md"):
            target=folder/filename
            if not target.exists():
                target.write_text(f"# {item['name']} — revisión de conexión\n\nEstado: PARTIAL. "
                    f"Véase ../../platform/supplied-integrations/2026-11-14/{filename}.\n\n"
                    f"Fuente: {code}. Sin nuevas afirmaciones de red o compatibilidad.\n\n"
                    f"Reproducir: `python {CENTRAL}/tools/verify_provider.py {item['id']}`.\n")
        lock=folder/"dependencies.lock.json"
        if not lock.exists():lock.write_text(json.dumps({"requirements":"requirements.txt","node_lock":"cloud/web/package-lock.json"},indent=2)+"\n")
        (folder/"tools").mkdir(exist_ok=True)
        (folder/"tools/integration_recipe.json").write_text(json.dumps({"tool":str(CENTRAL/"tools/verify_provider.py"),"provider_id":item["id"],"network":False},indent=2)+"\n")
        (folder/"tests").mkdir(exist_ok=True)
        (folder/"tests/INTEGRATION_TESTS.md").write_text(f"# Pruebas reutilizadas\n\n"
            f"`tests/test_supplied_integrations.py` comprueba `{item['id']}` dentro de los 57 métodos. "
            "`cloud/web/tests/supplied-integrations.test.mjs` comprueba transporte y contratos. "
            f"Comandos y límites: {CENTRAL}/REPRODUCE.md y RESULTS.md. No se inventa un fixture del proveedor.\n")
    print(f"Canonical connection records: {len(items)}")


if __name__=="__main__":main()

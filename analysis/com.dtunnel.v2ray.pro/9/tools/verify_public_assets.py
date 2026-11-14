#!/usr/bin/env python3
"""Verify the request identity is absent from built client/public assets."""
import argparse
import ast
import json
from pathlib import Path

ROOT=Path(__file__).resolve().parents[4]


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output",type=Path,required=True)
    args=parser.parse_args()
    tree=ast.parse((ROOT/"decoders/Python/apps/DTunnel_Mod/DTunnel.py").read_text())
    value=next(ast.literal_eval(node.value) for node in tree.body if isinstance(node,ast.Assign)
               and any(isinstance(target,ast.Name) and target.id=="DEFAULT_REQUEST_ID" for target in node.targets))
    needle=value.encode();findings=[];checked=0
    roots=[ROOT/"cloud/web/public",ROOT/"cloud/web/.next/static",ROOT/"android/app/src/main/assets"]
    if not all(folder.is_dir() for folder in roots):raise SystemExit("Build the web app before checking delivery assets")
    for folder in roots:
        for path in folder.rglob("*"):
            if path.is_file():
                checked+=1
                if needle in path.read_bytes():findings.append(str(path.relative_to(ROOT)))
    proof={"files_checked":checked,"public_asset_findings":findings,
           "public_assets_clean":not findings,"credential_value_recorded":False}
    args.output.parent.mkdir(parents=True,exist_ok=True)
    args.output.write_text(json.dumps(proof,indent=2)+"\n")
    print(json.dumps(proof))
    return bool(findings)


if __name__=="__main__":raise SystemExit(main())

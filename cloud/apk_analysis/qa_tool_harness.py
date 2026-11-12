"""F7-A8 bounded analyst harness, correlating vetted built-in observations.

The 63 historical researcher scripts are catalogued but remain DENY by default:
some are app-specific, require live credentials or instrument/execute untrusted
binaries. An input APK never selects arbitrary subprocess commands.
"""
from __future__ import annotations
from collections import defaultdict

from .qa_tool_plan import INVENTORY

MAX_CLASSES = 24
MAX_METHODS = 8
MAX_REFERENCES = 12

FRAMEWORK = (
    "android.", "androidx.", "java.", "javax.", "kotlin.",
    "com.google.", "com.facebook.", "com.onesignal.", "org.conscrypt.",
    "com.airbnb.", "com.trilead.", "net.i2p.", "org.apache.",
)


def _class_name(value: str) -> str:
    if not isinstance(value, str):
        return ""
    clean = value[1:-1].replace("/", ".") if value.startswith("L") and value.endswith(";") else value
    return clean[:190] if 1 < len(clean) <= 190 and all(
        c.isalnum() or c in "_.$" for c in clean
    ) else ""


def inspect_harness(inventory: dict, tooling: dict) -> dict:
    """Join per-class DEX code-item and Java reference evidence without leaking sources."""
    classes = defaultdict(lambda: {"methods": set(), "sources": set(),
                                  "indicators": set(), "codeItems": 0})
    for dex in inventory.get("dexHeaders", [])[:32]:
        if not isinstance(dex, dict):
            continue
        for method in dex.get("candidateMethods", [])[:64]:
            if not isinstance(method, dict):
                continue
            name = _class_name(method.get("class", ""))
            if not name or name.startswith(FRAMEWORK):
                continue
            if isinstance(method.get("name"), str) and len(method["name"]) <= 80:
                classes[name]["methods"].add(method["name"])
            classes[name]["sources"].add("DEX_METHOD_NAME")
        for item in dex.get("methodCodeEvidence", [])[:80]:
            if not isinstance(item, dict):
                continue
            name = _class_name(item.get("class", ""))
            if not name or name.startswith(FRAMEWORK):
                continue
            if item.get("status") == "CODE_ITEM_HASHED":
                classes[name]["codeItems"] += 1
                classes[name]["sources"].add("DEX_CODE_ITEM_SHA256")
    jadx = tooling.get("jadx", {})
    for site in jadx.get("candidateCallSites", [])[:96]:
        if not isinstance(site, dict):
            continue
        name = _class_name(site.get("class", ""))
        if not name or name.startswith(FRAMEWORK):
            continue
        if site.get("indicator") in (
            "JCA_CIPHER", "JCA_KEY_SPEC", "JCA_GCM", "JCA_MAC",
            "JCA_DIGEST", "JCA_PBKDF", "JNI_LOADER", "ANDROID_BASE64"
        ):
            classes[name]["indicators"].add(site["indicator"])
            classes[name]["sources"].add("JADX_REFERENCE")
        method = site.get("method", "")
        if isinstance(method, str) and method != "UNRESOLVED" and len(method) <= 80:
            classes[name]["methods"].add(method)
    recipes = jadx.get("methodRecipes", {})
    for item in recipes.get("methods", [])[:64]:
        name = _class_name(item.get("class", ""))
        if not name or name.startswith(FRAMEWORK):
            continue
        classes[name]["sources"].add("JADX_METHOD_BODY_SHA256")
        method = item.get("method", "")
        if isinstance(method, str) and len(method) <= 80:
            classes[name]["methods"].add(method)
    native_bindings = []
    for item in tooling.get("ghidra", {}).get("candidateFunctions", [])[:48]:
        native = item.get("name", "")
        if not isinstance(native, str) or not native.startswith("Java_"):
            continue
        for name, evidence in classes.items():
            owner = name.replace("_", "_1").replace(".", "_")
            prefix = "Java_" + owner + "_"
            if native.startswith(prefix) and len(native_bindings) < 24:
                native_bindings.append({"class": name, "nativeSymbol": native,
                    "binary": item.get("binary"), "evidence": "JNI_SYMBOL_OWNER_REFERENCE",
                    "decompilationCompleted": item.get("decompilationCompleted") is True,
                    "methodValidated": False})
                evidence["sources"].add("GHIDRA_JNI_SYMBOL")
    ordered = sorted(classes.items(), key=lambda entry: (
        -(int("DEX_CODE_ITEM_SHA256" in entry[1]["sources"])
          + int("JADX_REFERENCE" in entry[1]["sources"])
          + int("DEX_METHOD_NAME" in entry[1]["sources"])),
        -len(entry[1]["indicators"]), -entry[1]["codeItems"], entry[0]))
    candidates = [{
        "class": name,
        "methodsObserved": sorted(value["methods"])[:MAX_METHODS],
        "referenceIndicators": sorted(value["indicators"])[:MAX_REFERENCES],
        "dexCodeItemsHashed": value["codeItems"],
        "evidence": sorted(value["sources"]),
        "methodValidated": False,
    } for name, value in ordered[:MAX_CLASSES]]
    return {
        "schemaVersion": 1,
        "status": "STATIC_CROSS_REFERENCE_ONLY",
        "catalogue": {
            "registeredResearchScripts": len(INVENTORY),
            "researchScriptsAutoExecuted": 0,
            "selectionPolicy": "DENY_UNREVIEWED_RESEARCH_SCRIPTS",
        },
        "builtInPasses": [
            {"name": "APK_STRUCTURE", "executed": True},
            {"name": "DEX_TABLE_AND_CODE_ITEM", "executed": bool(inventory.get("dexHeaders"))},
            {"name": "ELF_NATIVE_METADATA", "executed": bool(inventory.get("nativeLibraries"))},
            {"name": "JADX_STATIC_REFERENCES",
             "executed": bool(jadx.get("attempted") or tooling.get("jadxAttempted"))},
            {"name": "JADX_METHOD_RECIPES", "executed": bool(recipes)},
            {"name": "GHIDRA_STATIC_FUNCTIONS", "executed": tooling.get("ghidraExecuted") is True},
            {"name": "CROSS_REFERENCE", "executed": True},
        ],
        "methodRecipeSummary": {
            "status": recipes.get("status", "NOT_AVAILABLE"),
            "methodsObserved": recipes.get("methodsObserved", 0),
            "methodsExported": len(recipes.get("methods", [])),
            "sameClassCalls": len(recipes.get("sameClassCalls", [])),
            "methodValidated": False,
        },
        "nativeBindings": native_bindings,
        "candidateClasses": candidates,
        "candidateClassesObserved": len(classes),
        "candidateClassesTruncated": len(classes) > MAX_CLASSES,
        "methodValidated": False,
        "codeExecuted": False,
    }

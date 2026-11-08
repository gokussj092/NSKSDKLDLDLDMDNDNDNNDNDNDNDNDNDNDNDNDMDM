"""F7-A7 evidence correlation and DENY-by-default catalogue of Work tools.

This is a compatibility planner, NOT an execution engine. The A0 inventory
lists research scripts but grants no right to run scripts, perform network
requests, instrument apps, or import unknown Python modules in the VPS.
"""
from __future__ import annotations

# Snapshot of the F7-A0 tool-sources inventory (exact repository paths).
# Original scripts, hashes and review status remain authoritative in analysis/.
INVENTORY = (
    "scripts/apk_analysis/abowaged_native_oracle.py",
    "scripts/apk_analysis/abowaged_verify.py",
    "scripts/apk_analysis/alfaisal_verify.py",
    "scripts/apk_analysis/am_liapp_metadata.py",
    "scripts/apk_analysis/am_liapp_native_probe.py",
    "scripts/apk_analysis/any_vpn_verify.py",
    "scripts/apk_analysis/apna_native_oracle.py",
    "scripts/apk_analysis/apna_verify.py",
    "scripts/apk_analysis/arm64_function.py",
    "scripts/apk_analysis/aura_net_verify.py",
    "scripts/apk_analysis/bd_net_native_oracle.py",
    "scripts/apk_analysis/bd_net_verify.py",
    "scripts/apk_analysis/creeb_verify.py",
    "scripts/apk_analysis/creeb_vpn_remote_probe.py",
    "scripts/apk_analysis/creeb_vpn_verify.py",
    "scripts/apk_analysis/decompile.py",
    "scripts/apk_analysis/dex_method.py",
    "scripts/apk_analysis/elf_inspect.py",
    "scripts/apk_analysis/enaa_verify.py",
    "scripts/apk_analysis/flexnet_b46_capture.js",
    "scripts/apk_analysis/flexnet_b46_grant_oracle.py",
    "scripts/apk_analysis/flexnet_collect_grant.py",
    "scripts/apk_analysis/flexnet_emulator_probe.py",
    "scripts/apk_analysis/go_inspect.py",
    "scripts/apk_analysis/ha_mod_strings.py",
    "scripts/apk_analysis/ha_runtime_capture.py",
    "scripts/apk_analysis/hex_custom_recover.py",
    "scripts/apk_analysis/hex_tunnel_recover.py",
    "scripts/apk_analysis/http_custom_probe.py",
    "scripts/apk_analysis/http_door_bundle.py",
    "scripts/apk_analysis/http_door_verify.py",
    "scripts/apk_analysis/inspect_apk.py",
    "scripts/apk_analysis/izph_verify.py",
    "scripts/apk_analysis/jyfast_vmp_strings.py",
    "scripts/apk_analysis/liapp_wrapper.py",
    "scripts/apk_analysis/mm_tunnel_source_check.py",
    "scripts/apk_analysis/mm_tunnel_verify.py",
    "scripts/apk_analysis/mnr_constants.py",
    "scripts/apk_analysis/mnr_verify.py",
    "scripts/apk_analysis/mtm_bundle.py",
    "scripts/apk_analysis/mtm_verify.py",
    "scripts/apk_analysis/netcol_source.py",
    "scripts/apk_analysis/netcol_verify.py",
    "scripts/apk_analysis/npv_recipient_capture.js",
    "scripts/apk_analysis/npv_termux_bundle.py",
    "scripts/apk_analysis/npv_termux.py",
    "scripts/apk_analysis/npvs_verify.py",
    "scripts/apk_analysis/oneftunnel_native_oracle.py",
    "scripts/apk_analysis/oneftunnel_verify.py",
    "scripts/apk_analysis/paranoid_strings.py",
    "scripts/apk_analysis/random_strings.py",
    "scripts/apk_analysis/sevennet_verify.py",
    "scripts/apk_analysis/speicers_verify.py",
    "scripts/apk_analysis/stringfog_strings.py",
    "scripts/apk_analysis/tunneldoom_verify.py",
    "scripts/apk_analysis/tx_tunnel_verify.py",
    "scripts/apk_analysis/ultra_tunnel_source_check.py",
    "scripts/apk_analysis/ultra_tunnel_verify.py",
    "scripts/apk_analysis/vector_icon.py",
    "scripts/apk_analysis/vip_snipher_verify.py",
    "scripts/apk_analysis/wolf_native_constants.py",
    "scripts/apk_analysis/wolf_verify.py",
    "scripts/apk_analysis/zig_verify.py",
)

CANDIDATES = (
    ("scripts/apk_analysis/dex_method.py", "DEX_METHOD_METADATA", "DEX"),
    ("scripts/apk_analysis/decompile.py", "JADX_OFFLINE", "DEX"),
    ("scripts/apk_analysis/inspect_apk.py", "APK_STRUCTURE", "DEX"),
    ("scripts/apk_analysis/elf_inspect.py", "ELF_HEADERS_SYMBOLS", "ELF"),
    ("scripts/apk_analysis/arm64_function.py", "ARM64_STATIC_FUNCTIONS", "ARM64"),
    ("scripts/apk_analysis/go_inspect.py", "GO_BUILD_METADATA", "ELF"),
    ("scripts/apk_analysis/stringfog_strings.py", "STRING_OBFUSCATION_REVIEW", "DEX"),
    ("scripts/apk_analysis/paranoid_strings.py", "STRING_OBFUSCATION_REVIEW", "DEX"),
    ("scripts/apk_analysis/random_strings.py", "STRING_OBFUSCATION_REVIEW", "DEX"),
)


def plan_tools(inventory: dict) -> dict:
    dex = inventory.get("dexHeaders", [])
    native = inventory.get("nativeLibraries", [])
    has_dex = any(x.get("tableStatus") == "PARSED" for x in dex)
    has_elf = any(x.get("sectionStatus") == "PARSED" for x in native)
    has_arm64 = any(x.get("architecture") == "AARCH64" for x in native)
    available = {"DEX": has_dex, "ELF": has_elf, "ARM64": has_arm64}
    selected = []
    for path, capability, target in CANDIDATES:
        if path in INVENTORY and available[target]:
            selected.append({
                "path": path, "capability": capability,
                "status": "CANDIDATE_REVIEW_REQUIRED",
                "executed": False,
                "compatibility": "INPUT_TYPE_ONLY_NOT_RUNTIME_VERIFIED",
            })
    return {
        "inventoryCount": len(INVENTORY),
        "sourceLanguages": {"python": sum(x.endswith(".py") for x in INVENTORY),
                            "javascript": sum(x.endswith(".js") for x in INVENTORY)},
        "policy": "DENY_UNREVIEWED_SCRIPTS",
        "automaticallyExecutedScripts": 0,
        "reviewCandidates": selected,
        "notSelectedCount": len(INVENTORY) - len(selected),
        "note": "Only built-in DEX/ELF parsers and pinned JADX run in this profile; existing research scripts require per-tool review.",
    }


def correlate_evidence(inventory: dict, tooling: dict) -> dict:
    """Bounded cross-component evidence without exporting secrets/source."""
    dex = inventory.get("dexHeaders", [])
    native = inventory.get("nativeLibraries", [])
    dex_refs = sorted({signal for item in dex for signal in item.get("cryptoReferences", [])
                       if isinstance(signal, str)})[:24]
    native_refs = sorted({signal for item in native for signal in item.get("cryptoReferences", [])
                          if isinstance(signal, str)})[:24]
    code_evidence_count = sum(len(item.get("methodCodeEvidence", [])) for item in dex)
    code_candidate_count = sum(int(item.get("candidateCodeItems", 0)) for item in dex)
    methods = [
        {"dex": item.get("name"), "class": method.get("class"),
         "name": method.get("name"), "evidence": method.get("evidence")}
        for item in dex if item.get("tableStatus") == "PARSED"
        for method in item.get("candidateMethods", []) if isinstance(method, dict)
    ][:48]
    j = tooling.get("jadx", {})
    recovered = j.get("recovery", {})
    return {
        "status": "REFERENCES_ONLY_NOT_VALIDATED",
        "dexParsed": inventory.get("dexParsed", 0),
        "dexObserved": inventory.get("dexFilesObserved", 0),
        "nativeParsed": inventory.get("elfParsed", 0),
        "nativeObserved": inventory.get("nativeFilesObserved", 0),
        "dexCryptoReferences": dex_refs,
        "nativeCryptoReferences": native_refs,
        "candidateMethods": methods,
        "candidateMethodsTruncated": sum(len(x.get("candidateMethods", [])) for x in dex) > len(methods),
        "dexCandidateCodeItems": code_candidate_count,
        "dexCodeEvidenceEntries": code_evidence_count,
        "jadxCandidateSites": len(j.get("candidateCallSites", [])),
        "jadxCandidateSitesTruncated": j.get("candidateCallSitesTruncated", False),
        "jadxRecoveredDexCount": recovered.get("dexRecovered", 0),
        "jadxDexDiscovered": recovered.get("dexDiscovered"),
        "methodValidated": False,
        "limitations": ["NO_CALL_GRAPH_PROOF", "NO_KEY_RECOVERY_CLAIM",
                        "DEX_METHOD_NAMES_ARE_HEURISTICS", "ELF_IMPORTS_ARE_SYMBOLS_ONLY"],
    }

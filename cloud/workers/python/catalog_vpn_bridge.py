#!/usr/bin/env python3
"""Private, offline, allowlisted C8 VPN catalog decoder bridge."""
from __future__ import annotations
import importlib
import json
import sys
from pathlib import Path

PROVIDERS = {
    "genis-vpn": "decoders.Python.apps.Genis_VPN.server_catalog_decoder",
    "speicers-turbo-vpn": "decoders.Python.apps.Speicers_Turbo_VPN.server_catalog_decoder",
    "http-conexion": "decoders.Python.apps.HTTP_Conexion.server_catalog_decoder",
    "namo-vpn": "decoders.Python.apps.NAMO_VPN.server_catalog_decoder",
    "fnf-tunnel-bd": "decoders.Python.apps.FNF_TUNNEL_BD.server_catalog_decoder",
    "alsaher-vip": "decoders.Python.apps.ALSAHER_VIP.server_catalog_decoder",
    "halcon-r-net": "decoders.Python.apps.Halcon_R_Net.server_catalog_decoder",
    "ha-tunnel-plus": "decoders.Python.apps.HA_Tunnel_Plus.server_catalog_decoder",
    "ultra-tunnel": "decoders.Python.apps.Ultra_Tunnel.server_catalog_decoder",
    "zig-tunnel": "decoders.Python.apps.ZiG_Tunnel.server_catalog_decoder",
    "enaa-tunnel": "decoders.Python.apps.Enaa_Tunnel.server_catalog_decoder",
    "alfaisal-tunnel-plus": "decoders.Python.apps.ALFAISAL_Tunnel_Plus.server_catalog_decoder",
    "izph-vpn-pro": "decoders.Python.apps.IZPH_VPN_PRO.server_catalog_decoder",
    "vip-snipher-pro": "decoders.Python.apps.VIP_Snipher_Pro.server_catalog_decoder",
    "netcol-vpn": "decoders.Python.apps.Netcol_VPN.server_catalog_decoder",
    "wolf-custom-vpn": "decoders.Python.apps.Wolf_Custom_VPN.server_catalog_decoder",
    "jyfast-vpn-ultra": "decoders.Python.apps.JyFast_VPN_Ultra.server_catalog_decoder",
    "tunneldoom-vpn": "decoders.Python.apps.TunnelDOOM_VPN.server_catalog_decoder",
    "mtm-tunnel-lite": "decoders.Python.apps.MTM_Tunnel_Lite.server_catalog_decoder",
    "mnr-tunnel-plus": "decoders.Python.apps.MNR_TUNNEL_PLUS.server_catalog_decoder",
    "bd-net-vpn": "decoders.Python.apps.BD_NET_VPN.server_catalog_decoder",
    "aura-net-vpn": "decoders.Python.apps.Aura_Net_VPN.server_catalog_decoder",
    "any-vpn": "decoders.Python.apps.ANY_VPN.server_catalog_decoder",
    "speicers-pro-vpn": "decoders.Python.apps.Speicers_Pro_VPN.server_catalog_decoder",
    "tx-tunnel": "decoders.Python.apps.Tx_Tunnel.server_catalog_decoder",
    # Build 47 hash POST is performed by the broker; this worker stays offline.
    "mm-tunnel": "decoders.Python.apps.MM_Tunnel.server_catalog_decoder",
    "creeb-vpn": "decoders.Python.apps.CREEB_VPN.server_catalog_decoder",
    "abowaged-vpn": "decoders.Python.apps.AboWaged_VPN.server_catalog_decoder",
    # Fixed APK updater validated independently from the stale embedded UpdaterLink.
    "apna-vpn": "decoders.Python.apps.APNA_VPN.server_catalog_decoder",
    "7net-vpn": "decoders.Python.apps.SevenNET_VPN.server_catalog_decoder",
    "xhypher-tunnel-pro": "decoders.Python.apps.Xhypher_Tunnel_Pro.server_catalog_decoder",
    "ut-loop-pro-vpn": "decoders.Python.apps.UT_Loop_Pro_VPN.server_catalog_decoder",
    "turbomx-vpn": "decoders.Python.apps.TurboMX_VPN.server_catalog_decoder",
    "superflash-vpn": "decoders.Python.apps.SuperFlash_VPN.server_catalog_decoder",
    "rmp-tunnel-pro": "decoders.Python.apps.RMP_TUNNEL_PRO.server_catalog_decoder",
    "rjc-tunnel-pro": "decoders.Python.apps.RJC_TUNNEL_PRO.server_catalog_decoder",
    "proneet-vpn": "decoders.Python.apps.ProNeet_VPN.server_catalog_decoder",
    "onspace-vpn": "decoders.Python.apps.OnSpace_VPN.server_catalog_decoder",
    "mx-tunnel-pro": "decoders.Python.apps.Mx_Tunnel_PRO.server_catalog_decoder",
    "megatunnel": "decoders.Python.apps.MegaTunnel.server_catalog_decoder",
    "http-internet-infinito": "decoders.Python.apps.HTTP_Internet_Infinito.server_catalog_decoder",
    "freedom-vpn": "decoders.Python.apps.FreedomVPN.server_catalog_decoder",
    "focus-vpn-cloud": "decoders.Python.apps.Focus_VPN_Cloud.server_catalog_decoder",
    "eut-vpn": "decoders.Python.apps.EUT_VPN.server_catalog_decoder",
    "v2ray-tunnel-plus": "decoders.Python.apps.V2ray_Tunnel_Plus.server_catalog_decoder",
    "tunelguard-vpn": "decoders.Python.apps.TunelGuard_VPN.server_catalog_decoder",
    "http-wakko": "decoders.Python.apps.HTTP_Wakko.server_catalog_decoder",
    "http-socketclay": "decoders.Python.apps.HTTP_SocketClay.server_catalog_decoder",
    "tunneltweak": "decoders.Python.apps.Tunneltweak.server_catalog_decoder",
    "http-jireh": "decoders.Python.apps.HTTP_Jireh.server_catalog_decoder",
    "http-fenixvpn": "decoders.Python.apps.HTTP_FenixVPN.server_catalog_decoder",
    "austroplus-vpn": "decoders.Python.apps.AustroPlus_VPN.server_catalog_decoder",
    "ac-tunnel-vpn": "decoders.Python.apps.AC_TUNNEL_VPN.server_catalog_decoder",
    "24clan-green": "decoders.Python.apps.24clan_VPN_Green.24clan_VPN_Green",
    "hx-tunnel": "decoders.Python.apps.HX_Tunnel_VPN.HX_Tunnel_VPN",
    "mkk-hyper": "decoders.Python.apps.MKK_Hyper_VPN.MKK_Hyper_VPN",
    "ksh-vpn": "decoders.Python.apps.KSH_VPN.ksh_vpn",
    "dtunnel-mod": "decoders.Python.apps.DTunnel_Mod.dtunnelmod",
    "my-tunnel-proxy": "decoders.Python.apps.My_Tunnel_Proxy.server_catalog_decoder",
    "robust-tunnel": "decoders.Python.apps.Robust_Tunnel_VPN.server_catalog_decoder",
    # Offline decoder; Royal's public card has an icon but decoding stays disabled.
    "royal-tunnel": "decoders.Python.apps.Royal_Tunnel_VPN.server_catalog_decoder",
    "trv-tunnel": "decoders.Python.apps.TRV_TUNNEL.server_catalog_decoder",
    "4u-tunnel-lite": "decoders.Python.apps.4U_TUNNEL_LITE.server_catalog_decoder",
}

def decode(provider_id: str, payload: bytes) -> str:
    module_name = PROVIDERS.get(provider_id)
    if module_name is None:
        raise ValueError("Unsupported provider")
    if provider_id=="mkk-hyper" and payload.startswith(b'{"kind":"spdecode-mkk-sources-v1"'):
        from cloud.workers.python.mkk_bundle import decode as decode_mkk_bundle
        result=decode_mkk_bundle(payload)
    else:
        module = importlib.import_module(module_name)
        result = module.run(payload)
    if not isinstance(result, str) or not result.strip():
        raise ValueError("Unable to decode complete catalog")
    # Reject malformed and incomplete catalogs, preserve original entire JSON.
    value = json.loads(result)
    if not isinstance(value, (dict, list)) or not value:
        raise ValueError("Invalid catalog result")
    return result

def main() -> int:
    if len(sys.argv)!=3:
        return 2
    try:
        data=Path(sys.argv[2]).read_bytes()
        limit=45*1024*1024 if sys.argv[1]=="mkk-hyper" else 8*1024*1024
        if not data or len(data)>limit:
            return 1
        rendered=decode(sys.argv[1],data)
        if sys.argv[1]=="mkk-hyper" and len(rendered.encode("utf-8"))>32*1024*1024:
            # Explicit, bounded error marker so the parent can return 413.
            # Never emit or truncate the actual configuration.
            sys.stdout.write('{"workerError":"OUTPUT_TOO_LARGE"}\n')
            return 3
    except (ValueError, OSError, ImportError, RecursionError):
        return 1
    sys.stdout.write(rendered)
    return 0

if __name__=="__main__":
    raise SystemExit(main())

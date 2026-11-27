from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .config import DECODERS_PATH, PROJECT_DIR

VALID_RUNTIMES = frozenset({"python", "node", "php"})


@dataclass(frozen=True, slots=True)
class DecoderSpec:
    extension: str
    name: str
    script: str
    runtime: str

    @property
    def script_path(self) -> Path:
        return PROJECT_DIR / self.script


def _normalize_extension(value: Any) -> str:
    extension = str(value).strip().lower().lstrip(".")
    if not extension:
        raise ValueError("Found an empty extension in decoders.json.")
    return extension


def load_decoder_registry(path: Path = DECODERS_PATH) -> dict[str, DecoderSpec]:
    if not path.exists():
        raise FileNotFoundError(f"Could not find the decoder registry: {path.name}")

    with path.open("r", encoding="utf-8") as registry_file:
        data = json.load(registry_file)

    raw_decoders = data.get("decoders") if isinstance(data, dict) else None
    if not isinstance(raw_decoders, dict) or not raw_decoders:
        raise ValueError("decoders.json must contain a nonempty 'decoders' object.")

    registry: dict[str, DecoderSpec] = {}
    for raw_extension, raw_spec in raw_decoders.items():
        extension = _normalize_extension(raw_extension)
        if not isinstance(raw_spec, dict):
            raise ValueError(f"Invalid configuration for '.{extension}'.")

        name = str(raw_spec.get("name", "")).strip()
        script = str(raw_spec.get("script", "")).strip()
        runtime = str(raw_spec.get("runtime", "")).strip().lower()
        if not name:
            raise ValueError(f"Falta 'name' para '.{extension}'.")
        if not script:
            raise ValueError(f"Falta 'script' para '.{extension}'.")
        if runtime not in VALID_RUNTIMES:
            raise ValueError(
                f"Invalid runtime for '.{extension}': {runtime!r}. "
                f"Allowed: {', '.join(sorted(VALID_RUNTIMES))}."
            )
        if Path(script).is_absolute() or ".." in Path(script).parts:
            raise ValueError(f"Ruta de script no permitida para '.{extension}': {script}")

        registry[extension] = DecoderSpec(
            extension=extension,
            name=name,
            script=script,
            runtime=runtime,
        )


    # Bot-only Python family. Android inventory deliberately stays pinned to
    # decoders.json until Android native parity is implemented separately.
    if path.resolve() == DECODERS_PATH.resolve():
        from decoders.Python.ultra import ULTRA_EXTS, ULTRA_NAMES

        for dotted_extension in sorted(ULTRA_EXTS):
            extension = _normalize_extension(dotted_extension)
            if extension in registry:
                # .ost already routes to the original OUSS Tunnel decoder.
                # That decoder tries the Ultra family as an authenticated
                # fallback if its legacy DES format is not recognized.
                if extension != "ost":
                    raise ValueError(f"Ultra registry conflicts with .{extension}")
                continue
            registry[extension] = DecoderSpec(
                extension=extension,
                name=ULTRA_NAMES[dotted_extension],
                script="decoders/Python/ultra.py",
                runtime="python",
            )


    # Additional bot-only RENZ/7NET family from the authorized 66.py source.
    # Keep decoders.json (the Android parity inventory) unchanged.
    if path.resolve() == DECODERS_PATH.resolve():
        from decoders.Python.renz import RENZ_FILE_EXTENSIONS, RENZ_FILE_NAMES

        for dotted_extension in sorted(RENZ_FILE_EXTENSIONS):
            extension = _normalize_extension(dotted_extension)
            if extension in registry:
                raise ValueError(f"RENZ registry conflicts with .{extension}")
            registry[extension] = DecoderSpec(
                extension=extension,
                name=RENZ_FILE_NAMES[dotted_extension],
                script="decoders/Python/renz.py",
                runtime="python",
            )


    # Standalone 2026 bot-only family modules (no Android catalog edits).
    if path.resolve() == DECODERS_PATH.resolve():
        from decoders.Python.config_batch_registry import file_decoder_specs

        for dotted_extension, (name, script) in file_decoder_specs().items():
            extension = _normalize_extension(dotted_extension)
            if extension in registry:
                raise ValueError(f"Bot decoder conflict with .{extension}")
            registry[extension] = DecoderSpec(
                extension=extension, name=name, script=script, runtime="python"
            )


    # Nine additional independent bot-only file engines from 66.py.
    # This deliberately does not alter the Android decoders.json catalog.
    if path.resolve() == DECODERS_PATH.resolve():
        from decoders.Python.config_independent_registry import (
            independent_file_decoder_specs,
        )

        for dotted_extension, (name, script) in independent_file_decoder_specs().items():
            extension = _normalize_extension(dotted_extension)
            if extension in registry:
                raise ValueError(f"Independent decoder conflict with .{extension}")
            registry[extension] = DecoderSpec(
                extension=extension, name=name, script=script, runtime="python"
            )

    # Bot-only generic source profiles: extension-specific keys, shared engines.
    # Preexisting format-specific decoders always win over legacy key tables.
    if path.resolve() == DECODERS_PATH.resolve():
        from decoders.Python.generic_profiles import generic_specs

        for dotted_extension, (name, script) in generic_specs(registry).items():
            extension = _normalize_extension(dotted_extension)
            if extension in registry:
                raise ValueError(f"Generic engine collision with .{extension}")
            registry[extension] = DecoderSpec(
                extension=extension, name=name, script=script, runtime="python"
            )


    # NUR TUNNEL .solid profile; never route catalog URLs through the bot.
    if path.resolve() == DECODERS_PATH.resolve():
        if "solid" in registry:
            raise ValueError("NUR Tunnel .solid decoder conflicts with an existing route")
        registry["solid"] = DecoderSpec(
            extension="solid", name="NUR TUNNEL VPN (.solid)",
            script="decoders/Python/nur_tunnel_solid.py", runtime="python"
        )

    if path.resolve() == DECODERS_PATH.resolve():
        if "1ftnl" in registry:
            raise ValueError("1FTunnel decoder conflicts with an existing route")
        registry["1ftnl"] = DecoderSpec(
            extension="1ftnl", name="1FTunnel 0.6.99",
            script="decoders/Python/apps/OneFTunnel/file_decoder.py", runtime="python"
        )

    if path.resolve() == DECODERS_PATH.resolve():
        if "nad" in registry:
            raise ValueError("NadiaVPN decoder conflicts with an existing route")
        registry["nad"] = DecoderSpec(
            extension="nad", name="NadiaVPN 1.4.6",
            script="decoders/Python/apps/NadiaVPN/file_decoder.py", runtime="python"
        )

    if path.resolve() == DECODERS_PATH.resolve():
        if "awg" in registry:
            raise ValueError("AboWaged .awg decoder conflicts with an existing route")
        registry["awg"] = DecoderSpec(
            extension="awg", name="AboWaged VPN 1.0",
            script="decoders/Python/apps/AboWaged_VPN/file_decoder.py", runtime="python"
        )

    if path.resolve() == DECODERS_PATH.resolve():
        if "creeb" in registry:
            raise ValueError("CREEB .creeb decoder conflicts with an existing route")
        registry["creeb"] = DecoderSpec(
            extension="creeb", name="CREEB INJECTOR 38.0",
            script="decoders/Python/apps/CREEB_INJECTOR/file_decoder.py", runtime="python"
        )

    if path.resolve() == DECODERS_PATH.resolve():
        # Exact 50.0 .crev route; .cer/.cerv retain the historical engine.
        registry["crev"] = DecoderSpec(
            extension="crev", name="CREEB VPN 50.0",
            script="decoders/Python/apps/CREEB_VPN/file_decoder.py", runtime="python"
        )

    if path.resolve() == DECODERS_PATH.resolve():
        if "kyz" in registry:
            raise ValueError("HTTP Door .kyz decoder conflicts with an existing route")
        registry["kyz"] = DecoderSpec(
            extension="kyz", name="HTTP Door 5.0",
            script="decoders/Python/apps/HTTP_Door/file_decoder.py", runtime="python"
        )

    if path.resolve() == DECODERS_PATH.resolve():
        if "stp" in registry:
            raise ValueError("MNR .stp decoder conflicts with an existing route")
        registry["stp"] = DecoderSpec(
            extension="stp", name="MNR TUNNEL PLUS 3.1",
            script="decoders/Python/apps/MNR_TUNNEL_PLUS/file_decoder.py", runtime="python"
        )

    if path.resolve() == DECODERS_PATH.resolve():
        registry["v2"] = DecoderSpec(
            extension="v2", name="e-V2Ray / MTM Tunnel Lite",
            script="decoders/Python/apps/MTM_Tunnel_Lite/file_decoder.py", runtime="python"
        )

    if path.resolve() == DECODERS_PATH.resolve():
        if "hexcm" in registry:
            raise ValueError("Hex Tunnel .hexcm decoder conflicts with an existing route")
        registry["hexcm"] = DecoderSpec(
            extension="hexcm", name="Hex Tunnel / HexVPN 1.7.3-Rev",
            script="decoders/Python/apps/Hex_Tunnel/file_decoder.py", runtime="python"
        )

    # CAT 102 (2026-11-27): STLRAY 1.1.36 (7 blocks; NO "gv" block —
    # generic_profiles.py already registers .gv -> generic_aes.py and a
    # duplicate would raise at load; the live bot path goes through
    # decoder_runtime -> engine, which dispatches .gv by content).
    if path.resolve() == DECODERS_PATH.resolve():
        if "sray" in registry:
            raise ValueError("STLRAY decoder conflicts with an existing route")
        registry["sray"] = DecoderSpec(
            extension="sray", name="STLRAY 1.1.36",
            script="decoders/Python/apps/STLRAY/file_decoder.py", runtime="python"
        )

    if path.resolve() == DECODERS_PATH.resolve():
        if "tvc" in registry:
            raise ValueError("STLRAY decoder conflicts with an existing route")
        registry["tvc"] = DecoderSpec(
            extension="tvc", name="STLRAY 1.1.36",
            script="decoders/Python/apps/STLRAY/file_decoder.py", runtime="python"
        )

    if path.resolve() == DECODERS_PATH.resolve():
        if "uv" in registry:
            raise ValueError("STLRAY decoder conflicts with an existing route")
        registry["uv"] = DecoderSpec(
            extension="uv", name="STLRAY 1.1.36",
            script="decoders/Python/apps/STLRAY/file_decoder.py", runtime="python"
        )

    if path.resolve() == DECODERS_PATH.resolve():
        if "gpx" in registry:
            raise ValueError("STLRAY decoder conflicts with an existing route")
        registry["gpx"] = DecoderSpec(
            extension="gpx", name="STLRAY 1.1.36",
            script="decoders/Python/apps/STLRAY/file_decoder.py", runtime="python"
        )

    if path.resolve() == DECODERS_PATH.resolve():
        if "test" in registry:
            raise ValueError("STLRAY decoder conflicts with an existing route")
        registry["test"] = DecoderSpec(
            extension="test", name="STLRAY 1.1.36",
            script="decoders/Python/apps/STLRAY/file_decoder.py", runtime="python"
        )

    if path.resolve() == DECODERS_PATH.resolve():
        if "insan" in registry:
            raise ValueError("STLRAY decoder conflicts with an existing route")
        registry["insan"] = DecoderSpec(
            extension="insan", name="STLRAY 1.1.36",
            script="decoders/Python/apps/STLRAY/file_decoder.py", runtime="python"
        )

    if path.resolve() == DECODERS_PATH.resolve():
        if "opq" in registry:
            raise ValueError("STLRAY decoder conflicts with an existing route")
        registry["opq"] = DecoderSpec(
            extension="opq", name="STLRAY 1.1.36",
            script="decoders/Python/apps/STLRAY/file_decoder.py", runtime="python"
        )

    if path.resolve() == DECODERS_PATH.resolve():
        if "asl" in registry:
            raise ValueError("ASL Tunnel decoder conflicts with an existing route")
        registry["asl"] = DecoderSpec(
            extension="asl", name="ASL TUNNEL 3.0",
            script="decoders/Python/apps/ASL_Tunnel/file_decoder.py", runtime="python"
        )

    if path.resolve() == DECODERS_PATH.resolve():
        if "rj" in registry:
            raise ValueError("ExoticFast VIP decoder conflicts with an existing route")
        registry["rj"] = DecoderSpec(
            extension="rj", name="ExoticFast VIP",
            script="decoders/Python/apps/ExoticFast_VIP/file_decoder.py", runtime="python"
        )

    if path.resolve() == DECODERS_PATH.resolve():
        if "reese" in registry:
            raise ValueError("REESE TUNNEL decoder conflicts with an existing route")
        registry["reese"] = DecoderSpec(
            extension="reese", name="REESE TUNNEL 3.23.28",
            script="decoders/Python/apps/REESE_TUNNEL/reese_tunnel.py", runtime="python"
        )

    return registry


DECODER_REGISTRY = load_decoder_registry()


def get_supported_extension(filename: str) -> str | None:
    """Detecta extensiones simples y compuestas, por ejemplo .sksrv.png."""
    lower_name = filename.lower()
    for extension in sorted(DECODER_REGISTRY, key=len, reverse=True):
        if lower_name.endswith(f".{extension}"):
            return extension
    return None


def get_decoder(extension: str) -> DecoderSpec:
    return DECODER_REGISTRY[extension.lower().lstrip(".")]


def validate_decoder_files() -> list[str]:
    """Report registry errors without running decoders."""
    errors: list[str] = []
    for extension, spec in DECODER_REGISTRY.items():
        if not spec.script_path.is_file():
            errors.append(f".{extension}: missing {spec.script}")
    return errors

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
        raise ValueError("Se encontró una extensión vacía en decoders.json.")
    return extension


def load_decoder_registry(path: Path = DECODERS_PATH) -> dict[str, DecoderSpec]:
    if not path.exists():
        raise FileNotFoundError(f"No se encontró el registro de decodificadores: {path.name}")

    with path.open("r", encoding="utf-8") as registry_file:
        data = json.load(registry_file)

    raw_decoders = data.get("decoders") if isinstance(data, dict) else None
    if not isinstance(raw_decoders, dict) or not raw_decoders:
        raise ValueError("decoders.json debe contener un objeto 'decoders' no vacío.")

    registry: dict[str, DecoderSpec] = {}
    for raw_extension, raw_spec in raw_decoders.items():
        extension = _normalize_extension(raw_extension)
        if not isinstance(raw_spec, dict):
            raise ValueError(f"Configuración inválida para '.{extension}'.")

        name = str(raw_spec.get("name", "")).strip()
        script = str(raw_spec.get("script", "")).strip()
        runtime = str(raw_spec.get("runtime", "")).strip().lower()
        if not name:
            raise ValueError(f"Falta 'name' para '.{extension}'.")
        if not script:
            raise ValueError(f"Falta 'script' para '.{extension}'.")
        if runtime not in VALID_RUNTIMES:
            raise ValueError(
                f"Runtime inválido para '.{extension}': {runtime!r}. "
                f"Permitidos: {', '.join(sorted(VALID_RUNTIMES))}."
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
    """Devuelve una lista de errores del registro sin ejecutar ningún decodificador."""
    errors: list[str] = []
    for extension, spec in DECODER_REGISTRY.items():
        if not spec.script_path.is_file():
            errors.append(f".{extension}: no existe {spec.script}")
    return errors

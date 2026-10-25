#!/usr/bin/env python3
"""Shared .v2 route: MTM catalog or the unchanged historical e-V2Ray reader."""
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[4]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
from decoders.Python.apps.MTM_Tunnel_Lite import codec
from decoders.Python import EV2RAY


def _decode(data: bytes) -> tuple[str | None, bool]:
    try:
        plain = codec.decode_bytes(data)
    except ValueError:
        return (EV2RAY.run(data) if isinstance(data, bytes) and len(data) <= 16 * 1024 * 1024 else None), True
    # Successfully opened MTM-format bytes must validate as a full catalog.
    # A malformed catalog must not be reinterpreted as another application.
    try:
        return codec.render(codec.parse_catalog(plain)), False
    except (ValueError, RecursionError):
        return None, False


def run(data: bytes) -> str | None:
    return _decode(data)[0]


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit(2)
    try:
        with Path(sys.argv[1]).open("rb") as stream:
            result, legacy = _decode(stream.read(16 * 1024 * 1024 + 1))
        if result is None:
            raise ValueError("Invalid catalog/profile")
    except (ValueError, OSError, RecursionError):
        print("No se pudo descifrar el archivo .v2 completo.", file=sys.stderr)
        raise SystemExit(1)
    sys.stdout.write(result)
    if legacy:
        # EV2RAY.main uses print(run(...)); preserve its extra newline exactly.
        sys.stdout.write("\n")

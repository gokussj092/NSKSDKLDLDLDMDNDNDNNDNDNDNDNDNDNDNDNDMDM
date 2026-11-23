from __future__ import annotations

import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

from .config import PROJECT_DIR
from .registry import DecoderSpec


@dataclass(frozen=True, slots=True)
class DecoderExecutionResult:
    returncode: int
    stdout: str
    stderr: str

    @property
    def output(self) -> str:
        return self.stdout or self.stderr or "The script produced no output."


def build_decoder_command(spec: DecoderSpec, input_file: Path) -> list[str]:
    if spec.runtime == "python":
        runtime = sys.executable
    else:
        runtime = shutil.which(spec.runtime)
        if runtime is None:
            display_name = {"node": "Node.js", "php": "PHP"}.get(spec.runtime, spec.runtime)
            raise FileNotFoundError(
                f"{display_name} is not installed or is unavailable on PATH"
            )

    if not spec.script_path.is_file():
        raise FileNotFoundError(f"Could not find the decoder: {spec.script}")

    return [runtime, str(spec.script_path), str(input_file)]


def execute_decoder(
    spec: DecoderSpec,
    input_file: Path,
    *,
    timeout_seconds: int,
) -> DecoderExecutionResult:
    """Run a decoder from the project root."""
    command = build_decoder_command(spec, input_file)
    result = subprocess.run(
        command,
        cwd=PROJECT_DIR,
        text=True,
        encoding="utf-8",
        errors="replace",
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=timeout_seconds,
        check=False,
    )
    return DecoderExecutionResult(
        returncode=result.returncode,
        stdout=result.stdout.strip(),
        stderr=result.stderr.strip(),
    )

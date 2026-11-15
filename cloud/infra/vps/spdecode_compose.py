"""Compose arguments for operator helpers that may recreate production services."""
from pathlib import Path


def compose_command(base: Path, environment: Path, *args: str) -> list[str]:
    command = ["docker", "compose", "--project-name", "spdecode",
               "--env-file", str(environment), "-f", str(base)]
    resources = environment.parent / "compose.resources.yaml"
    if resources.exists() or resources.is_symlink():
        if not resources.is_file():
            raise RuntimeError("Resource override is not a readable file")
        # Verify readability without parsing, logging or changing operator data.
        with resources.open("rb"):
            pass
        command.extend(["-f", str(resources)])
    return command + list(args)

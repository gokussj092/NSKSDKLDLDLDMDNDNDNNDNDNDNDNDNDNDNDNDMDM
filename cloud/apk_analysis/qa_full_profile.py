"""Operator-owned full-tool budgets; an APK cannot request more resources."""
from __future__ import annotations

GIB = 1024 ** 3
STANDARD = {
    "name": "FULL_STANDARD", "minimumMemory": 3 * GIB,
    "heap": "1800m", "threads": 2, "jadxMode": "auto",
    "primarySeconds": 240, "jadxSeconds": 420, "jobSeconds": 840,
    "recoveryDex": 16, "recoverySeconds": 90,
    "nativeLibraries": 8, "nativeBytes": 64 * 1024 * 1024,
    "ghidraAnalysisSeconds": 120, "ghidraProcessSeconds": 240,
}
LARGE = {
    "name": "FULL_12GB_HOST", "minimumMemory": 7 * GIB,
    "heap": "4096m", "threads": 3, "jadxMode": "auto",
    "primarySeconds": 420, "jadxSeconds": 900, "jobSeconds": 1680,
    "recoveryDex": 32, "recoverySeconds": 120,
    "nativeLibraries": 16, "nativeBytes": 64 * 1024 * 1024,
    "ghidraAnalysisSeconds": 180, "ghidraProcessSeconds": 360,
}

def full_profile(container_memory: int) -> dict:
    if type(container_memory) is not int or container_memory < STANDARD["minimumMemory"]:
        raise ValueError("INSUFFICIENT_CONTAINER_MEMORY")
    return dict(LARGE if container_memory >= LARGE["minimumMemory"] else STANDARD)

def remaining_seconds(deadline: float, now: float, ceiling: int) -> int:
    if type(ceiling) is not int or ceiling < 1:
        raise ValueError("INVALID_TOOL_BUDGET")
    return max(0, min(ceiling, int(deadline - now)))

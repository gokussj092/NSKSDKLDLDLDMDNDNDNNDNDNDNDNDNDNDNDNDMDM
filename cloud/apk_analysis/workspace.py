"""F7-A0-P03 host-owned APK workspace lifecycle.

The trusted orchestrator owns this module. The untrusted analysis container
receives ONLY an individual writable job directory and read-only tool cache.
It MUST NEVER receive the state directory, result store or Docker socket.

No APK inspection/decryption occurs here. A durable result receipt must be
confirmed by the trusted application service before final cleanup.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import re
import shutil
import stat
import tempfile
import uuid

ID = re.compile(r"[0-9a-f]{32}")
DIGEST = re.compile(r"[0-9a-f]{64}")
REF = re.compile(r"[A-Za-z0-9][A-Za-z0-9/_:-]{0,190}")
TERMINAL = frozenset({"RESULT_PERSISTED", "CLOSED_NO_RESULT"})
UMASK_SAFE = 0o700


class WorkspaceError(ValueError):
    pass


def validate_id(job_id: str) -> str:
    if not isinstance(job_id, str) or not ID.fullmatch(job_id):
        raise WorkspaceError("Invalid job identifier")
    return job_id


def _no_symlink(path: Path) -> None:
    if path.is_symlink():
        raise WorkspaceError("Symlinked workspace path denied")


class WorkspaceStore:
    """On-disk host-only bookkeeping; analysis subprocess may not access state.

    Expected layout:
        root/tool-cache  (persistent verified binary cache)
        root/jobs/<id>   (per-job input/scratch/output staging)
        root/state/<id>.json  (host-only durable completion receipt)
    """

    def __init__(self, root: Path):
        root = Path(root).absolute()
        if root.resolve() != root:
            raise WorkspaceError("Symlinked ancestor denied")
        self.root = root
        self.jobs = root / "jobs"
        self.cache = root / "tool-cache"
        self.state = root / "state"

    def initialize(self) -> None:
        # Existing directories must already be private. Never chmod a shared
        # directory to make an unsafe deployment appear safe.
        for directory in (self.root, self.jobs, self.cache, self.state):
            _no_symlink(directory)
            if directory.exists():
                if not directory.is_dir() or directory.stat().st_mode & 0o077:
                    raise WorkspaceError("Storage directory must be private (0700)")
            else:
                directory.mkdir(mode=0o700, parents=False)
            _no_symlink(directory)

    def _paths(self, job_id: str) -> tuple[Path, Path]:
        validate_id(job_id)
        return self.jobs / job_id, self.state / (job_id + ".json")

    def _load(self, job_id: str) -> dict:
        _, path = self._paths(job_id)
        _no_symlink(path)
        try:
            state = json.loads(path.read_text("utf-8"))
        except (OSError, ValueError) as exc:
            raise WorkspaceError("No valid trusted job state") from exc
        if not isinstance(state, dict) or state.get("job_id") != job_id:
            raise WorkspaceError("Job state mismatch")
        return state

    def _save(self, job_id: str, payload: dict) -> None:
        _, dest = self._paths(job_id)
        _no_symlink(dest)
        if not self.state.is_dir() or self.state.stat().st_mode & 0o077:
            raise WorkspaceError("Untrusted state directory")
        fd, tmpname = tempfile.mkstemp(prefix=".state-", dir=self.state)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as stream:
                json.dump(payload, stream, sort_keys=True, separators=(",", ":"))
                stream.flush()
                os.fsync(stream.fileno())
            os.chmod(tmpname, 0o600)
            os.replace(tmpname, dest)
        finally:
            if os.path.lexists(tmpname):
                os.unlink(tmpname)

    def create(self, job_id: str | None = None) -> str:
        self.initialize()
        job_id = validate_id(job_id or uuid.uuid4().hex)
        target, marker = self._paths(job_id)
        if marker.exists() or marker.is_symlink():
            raise WorkspaceError("Duplicate job receipt")
        target.mkdir(mode=0o700, exist_ok=False)
        for child in ("input", "scratch", "output-staging"):
            (target / child).mkdir(mode=0o700, exist_ok=False)
        marker_file = target / ".spdecode-job"
        fd = os.open(marker_file, os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, "O_NOFOLLOW", 0), 0o600)
        with os.fdopen(fd, "w") as f:
            f.write(job_id)
        self._save(job_id, {"job_id": job_id, "status": "IN_PROGRESS"})
        return job_id

    def mark_awaiting_human(self, job_id: str) -> None:
        state = self._load(job_id)
        if state["status"] != "IN_PROGRESS":
            raise WorkspaceError("Cannot escalate this state")
        self._save(job_id, {"job_id": job_id, "status": "AWAITING_HUMAN"})
        # The job data is not purged: human review may need the original APK.

    def result_persisted(self, job_id: str, digest_sha256: str, result_ref: str, *, cleanup: bool = True) -> None:
        """Trusted server calls ONLY after confirming durable result storage.

        The analysis container must not call this, nor choose digest/result_ref.
        This method does not itself verify remote storage persistence.
        """
        state = self._load(job_id)
        if state["status"] not in ("IN_PROGRESS", "AWAITING_HUMAN"):
            raise WorkspaceError("Job already finalized")
        if not isinstance(digest_sha256, str) or not DIGEST.fullmatch(digest_sha256):
            raise WorkspaceError("Invalid retained result SHA-256")
        if not isinstance(result_ref, str) or not REF.fullmatch(result_ref):
            raise WorkspaceError("Invalid retained result reference")
        self._save(job_id, {"job_id": job_id, "status": "RESULT_PERSISTED",
                            "result_sha256": digest_sha256, "result_ref": result_ref})
        if cleanup:
            self.cleanup(job_id)

    def close_without_result(self, job_id: str, *, cleanup: bool = True) -> None:
        """Trusted service confirms terminal failure/no support obligation."""
        state = self._load(job_id)
        if state["status"] not in ("IN_PROGRESS", "AWAITING_HUMAN"):
            raise WorkspaceError("Job already finalized")
        self._save(job_id, {"job_id": job_id, "status": "CLOSED_NO_RESULT"})
        if cleanup:
            self.cleanup(job_id)

    def cleanup(self, job_id: str) -> bool:
        self.initialize()
        target, _ = self._paths(job_id)
        state = self._load(job_id)
        if state["status"] == "WORKSPACE_PURGED":
            return False
        if state["status"] not in TERMINAL:
            raise WorkspaceError("Cannot purge unfinished or human-pending job")
        _no_symlink(target)
        if target.exists():
            if not target.is_dir():
                raise WorkspaceError("Job workspace is not a directory")
            marker = target / ".spdecode-job"
            _no_symlink(marker)
            if not marker.is_file() or marker.read_text("utf-8") != job_id:
                raise WorkspaceError("Job ownership marker mismatch")
            if not shutil.rmtree.avoids_symlink_attacks:
                raise WorkspaceError("Platform lacks fd-based symlink-safe cleanup")
            shutil.rmtree(target)
        state["status"] = "WORKSPACE_PURGED"
        self._save(job_id, state)
        return True

    def reap_completed(self) -> list[str]:
        """Crash recovery: ONLY terminal jobs. Never age-delete active jobs."""
        self.initialize()
        cleaned = []
        for entry in sorted(self.state.iterdir()):
            if entry.is_symlink() or not entry.is_file() or not entry.name.endswith(".json"):
                continue
            job_id = entry.name[:-5]
            if not ID.fullmatch(job_id):
                continue
            state = self._load(job_id)
            if state["status"] in TERMINAL and self.cleanup(job_id):
                cleaned.append(job_id)
        return cleaned

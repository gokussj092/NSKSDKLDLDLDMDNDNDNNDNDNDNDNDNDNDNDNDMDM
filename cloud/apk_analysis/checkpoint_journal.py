"""F7-A0-P04: host-owned, append-only APK analysis checkpoint journal.

Metadata only: no APK bytes, decrypted payload, credentials, endpoints or logs.
The untrusted sandbox MUST NOT access this directory or call this module.
Artifact refs point to a separate durable encrypted store (A4/A5 pending).

Linux: fsync + atomic rename + advisory flock. A crash before rename leaves
only a dot-prefixed temporary file, excluded from the committed event chain.
No claim of cross-host durability or encrypted at-rest metadata is made here.
"""
from __future__ import annotations

from contextlib import contextmanager
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import tempfile
import time

JOB = re.compile(r"[a-f0-9]{32}\Z")
DIGEST = re.compile(r"[a-f0-9]{64}\Z")
OBJECT = re.compile(r"obj:[a-f0-9]{32}\Z")
PROOF_REF = re.compile(r"proof:[a-f0-9]{32}\Z")
AUTH_REF = re.compile(r"auth:[a-f0-9]{32}\Z")
TOOL = re.compile(r"[a-z][a-z0-9_-]{1,63}\Z")
STAGES = ("UPLOAD_VALIDATED", "STATIC_INVENTORY", "RESOURCES", "DEX", "ELF",
          "METHOD_REVIEW", "REPORT")
STATUSES = frozenset({"OK", "PARTIAL", "FAILED", "NEEDS_HUMAN"})
EVIDENCE = frozenset({"UNKNOWN", "OBSERVED", "INFERRED", "VERIFIED_SYNTHETIC", "VERIFIED_REAL"})
PRIVACY = frozenset({"USER_PRIVATE", "ADMIN_RESTRICTED"})
ERRORS = frozenset({"TOOL_TIMEOUT", "INPUT_INVALID", "TOOL_CRASH", "NETWORK_UNAVAILABLE",
                    "DEPENDENCY_MISSING", "EVIDENCE_INCOMPLETE", "NO_MATCH",
                    "SANDBOX_DENIED", "INTERNAL_ERROR"})
REC_FIELDS = frozenset({
    "stage", "status", "evidence", "privacy", "tool_id", "tool_sha256",
    "input_sha256", "artifact_ref", "artifact_sha256", "artifact_bytes",
    "error_code", "verification_ref", "authorization_ref"
})
ZERO = "0" * 64
MAX_ARTIFACT_BYTES = 512 * 1024 * 1024


class CheckpointError(ValueError):
    pass


def _canonical(data: dict) -> bytes:
    return json.dumps(data, sort_keys=True, ensure_ascii=True,
                      separators=(",", ":"), allow_nan=False).encode("utf-8")


def _digest(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _unique_pairs(pairs):
    output = {}
    for name, value in pairs:
        if name in output:
            raise CheckpointError("Duplicate checkpoint JSON key")
        output[name] = value
    return output


def validate_record(record: dict) -> None:
    if not isinstance(record, dict) or set(record) != REC_FIELDS:
        raise CheckpointError("Checkpoint schema fields mismatch")
    if record["stage"] not in STAGES or record["status"] not in STATUSES:
        raise CheckpointError("Unknown checkpoint stage/status")
    if record["evidence"] not in EVIDENCE or record["privacy"] not in PRIVACY:
        raise CheckpointError("Unsupported evidence/privacy class")
    if not isinstance(record["tool_id"], str) or not TOOL.fullmatch(record["tool_id"]):
        raise CheckpointError("Tool ID must be a safe identifier")
    for key in ("tool_sha256", "input_sha256"):
        if not isinstance(record[key], str) or not DIGEST.fullmatch(record[key]):
            raise CheckpointError("Missing SHA-256 provenance")
    ref, sha, size = record["artifact_ref"], record["artifact_sha256"], record["artifact_bytes"]
    if not isinstance(size, int) or isinstance(size, bool) or not 0 <= size <= MAX_ARTIFACT_BYTES:
        raise CheckpointError("Invalid artifact byte count")
    if ref is None:
        if sha is not None or size != 0:
            raise CheckpointError("Artifact fields must be all absent")
    elif (not isinstance(ref, str) or not OBJECT.fullmatch(ref)
          or not isinstance(sha, str) or not DIGEST.fullmatch(sha) or size == 0):
        raise CheckpointError("Incomplete artifact receipt")
    if record["status"] == "OK" and ref is None:
        raise CheckpointError("Successful stage requires a durable artifact reference")
    code = record["error_code"]
    if record["status"] in ("FAILED", "NEEDS_HUMAN") and code not in ERRORS:
        raise CheckpointError("Failure/human stage needs a bounded error code")
    if record["status"] == "OK" and code is not None:
        raise CheckpointError("Success cannot carry an error code")
    if code is not None and code not in ERRORS:
        raise CheckpointError("Unrecognized reason code")
    proof, auth = record["verification_ref"], record["authorization_ref"]
    if proof is not None and (not isinstance(proof, str) or not PROOF_REF.fullmatch(proof)):
        raise CheckpointError("Invalid independent verification reference")
    if auth is not None and (not isinstance(auth, str) or not AUTH_REF.fullmatch(auth)):
        raise CheckpointError("Invalid authorization reference")
    if record["evidence"] == "VERIFIED_REAL" and (proof is None or auth is None):
        raise CheckpointError("Real evidence requires independent proof and authorization")
    if record["evidence"] == "VERIFIED_SYNTHETIC" and proof is None:
        raise CheckpointError("Synthetic verification also needs a proof reference")
    # Presence of refs alone does not independently prove real verification:
    # their signatures and scope must be enforced by A5's trusted evidence service.


def checkpoint_record(*, stage: str, status: str, evidence: str, privacy: str,
                      tool_id: str, tool_sha256: str, input_sha256: str,
                      artifact_ref: str | None = None, artifact_sha256: str | None = None,
                      artifact_bytes: int = 0, error_code: str | None = None,
                      verification_ref: str | None = None,
                      authorization_ref: str | None = None) -> dict:
    rec = {key: value for key, value in locals().items()}
    validate_record(rec)
    return rec


def _secure_dir(path: Path) -> None:
    """Create or validate a private directory, safe against concurrent writers.

    Parallel journal threads may both observe an absent directory; catching
    only EEXIST preserves atomic creation without widening permissions.
    Symlinks, regular files and group/world-accessible dirs fail closed.
    """
    if path.is_symlink():
        raise CheckpointError("Symlinked checkpoint directory prohibited")
    try:
        path.mkdir(mode=0o700)
    except FileExistsError:
        pass
    if path.is_symlink():
        raise CheckpointError("Symlinked checkpoint directory prohibited")
    if not path.is_dir() or (path.stat().st_mode & 0o077):
        raise CheckpointError("Checkpoint directory must be private (0700)")


def _fsync_dir(path: Path) -> None:
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


class CheckpointJournal:
    """Single-host durable metadata contract with writer serialization.

    Lock files and checkpoint JSON are host-only, outside writable job folders.
    A4/A5 must own authentication, encrypted object storage and verification.
    """

    def __init__(self, root: Path):
        self.root = Path(os.path.abspath(root))
        if self.root.resolve() != self.root:
            raise CheckpointError("Symlinked checkpoint root prohibited")

    def _job_dir(self, job_id: str) -> Path:
        if not isinstance(job_id, str) or not JOB.fullmatch(job_id):
            raise CheckpointError("Invalid job ID")
        return self.root / job_id

    @contextmanager
    def _locked(self, job_id: str):
        _secure_dir(self.root)
        folder = self._job_dir(job_id)
        _secure_dir(folder)
        lock = folder / ".lock"
        if lock.is_symlink():
            raise CheckpointError("Symlink lock file prohibited")
        flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(lock, flags, 0o600)
        try:
            if os.fstat(fd).st_mode & 0o077:
                raise CheckpointError("Insecure checkpoint lock")
            fcntl.flock(fd, fcntl.LOCK_EX)
            yield folder
        finally:
            fcntl.flock(fd, fcntl.LOCK_UN)
            os.close(fd)

    def _read_events(self, folder: Path, job_id: str) -> list[dict]:
        all_names = []
        for p in folder.iterdir():
            if p.name.startswith("."):
                continue
            if p.is_symlink() or not p.is_file() or not re.fullmatch(r"[0-9]{8}\.json", p.name):
                raise CheckpointError("Unexpected file inside journal")
            all_names.append(p)
        events = []
        previous = ZERO
        previous_stage = -1
        for number, path in enumerate(sorted(all_names), start=1):
            if path.name != f"{number:08d}.json":
                raise CheckpointError("Missing or reordered checkpoint event")
            if path.stat().st_mode & 0o077:
                raise CheckpointError("Checkpoint event permissions too broad")
            try:
                event = json.loads(path.read_bytes(), object_pairs_hook=_unique_pairs)
            except (ValueError, TypeError, UnicodeError) as exc:
                raise CheckpointError("Corrupted checkpoint event") from exc
            if set(event) != {"schema_version", "event_type", "job_id", "sequence",
                              "recorded_at_unix", "previous_sha256", "record", "event_sha256"}:
                raise CheckpointError("Unknown event schema")
            if (event["schema_version"] != 1 or event["job_id"] != job_id
                or type(event["sequence"]) is not int or event["sequence"] != number
                or type(event["recorded_at_unix"]) is not int or event["recorded_at_unix"] < 0
                or event["previous_sha256"] != previous):
                raise CheckpointError("Checkpoint chain sequence mismatch")
            event_hash = event.pop("event_sha256")
            if not isinstance(event_hash, str) or not DIGEST.fullmatch(event_hash):
                raise CheckpointError("Bad checkpoint chain digest")
            if event_hash != _digest(_canonical(event)):
                raise CheckpointError("Checkpoint event integrity mismatch")
            event["event_sha256"] = event_hash
            kind = event["event_type"]
            if kind == "CHECKPOINT":
                validate_record(event["record"])
                stage_index = STAGES.index(event["record"]["stage"])
                if stage_index < previous_stage:
                    raise CheckpointError("Checkpoint stage moved backwards")
                previous_stage = stage_index
            elif kind == "RESULT_COMMITTED":
                if number == 1 or events[-1]["event_type"] == "RESULT_COMMITTED":
                    raise CheckpointError("Invalid finalization")
                if not isinstance(event["record"], dict) or set(event["record"]) != {
                    "result_ref", "result_sha256", "result_bytes", "report_checkpoint_sha256"
                }:
                    raise CheckpointError("Invalid final result record")
                out = event["record"]
                if (not isinstance(out["result_ref"], str) or not OBJECT.fullmatch(out["result_ref"])
                    or not isinstance(out["result_sha256"], str) or not DIGEST.fullmatch(out["result_sha256"])
                    or type(out["result_bytes"]) is not int or not 1 <= out["result_bytes"] <= MAX_ARTIFACT_BYTES
                    or not isinstance(out["report_checkpoint_sha256"], str)
                    or not DIGEST.fullmatch(out["report_checkpoint_sha256"])):
                    raise CheckpointError("Invalid final result receipt")
                report = events[-1]
                if report["event_type"] != "CHECKPOINT" or report["record"]["stage"] != "REPORT":
                    raise CheckpointError("Missing successful report checkpoint")
                if report["record"]["status"] != "OK":
                    raise CheckpointError("Report checkpoint not successful")
                if (out["report_checkpoint_sha256"] != report["event_sha256"]
                    or out["result_ref"] != report["record"]["artifact_ref"]
                    or out["result_sha256"] != report["record"]["artifact_sha256"]
                    or out["result_bytes"] != report["record"]["artifact_bytes"]):
                    raise CheckpointError("Final receipt does not match report")
            else:
                raise CheckpointError("Unknown event type")
            if events and events[-1]["event_type"] == "RESULT_COMMITTED":
                raise CheckpointError("Checkpoint after final result")
            events.append(event)
            previous = event_hash
        return events

    def inspect(self, job_id: str) -> dict:
        # Read under lock to avoid transient snapshots during atomic replace.
        with self._locked(job_id) as folder:
            events = self._read_events(folder, job_id)
        latest = events[-1] if events else None
        return {
            "job_id": job_id, "sequence": len(events),
            "last_event_sha256": latest["event_sha256"] if latest else ZERO,
            "final": latest is not None and latest["event_type"] == "RESULT_COMMITTED",
            "events": events,
        }

    def _append(self, folder: Path, job_id: str, events: list[dict],
                event_type: str, record: dict) -> dict:
        seq = len(events) + 1
        event = {
            "schema_version": 1, "event_type": event_type, "job_id": job_id,
            "sequence": seq, "recorded_at_unix": int(time.time()),
            "previous_sha256": events[-1]["event_sha256"] if events else ZERO,
            "record": record,
        }
        event["event_sha256"] = _digest(_canonical(event))
        destination = folder / f"{seq:08d}.json"
        if destination.exists() or destination.is_symlink():
            raise CheckpointError("Checkpoint sequence already committed")
        fd, tmp = tempfile.mkstemp(prefix=".event-", dir=folder)
        try:
            with os.fdopen(fd, "wb") as file:
                file.write(_canonical(event) + b"\n")
                file.flush()
                os.fsync(file.fileno())
            os.chmod(tmp, 0o600)
            os.replace(tmp, destination)
            _fsync_dir(folder)
        finally:
            if os.path.lexists(tmp):
                os.unlink(tmp)
        return event

    def append_checkpoint(self, job_id: str, record: dict) -> dict:
        validate_record(record)
        with self._locked(job_id) as folder:
            events = self._read_events(folder, job_id)
            if events and events[-1]["event_type"] == "RESULT_COMMITTED":
                raise CheckpointError("Finalized job cannot accept further stages")
            if events and STAGES.index(record["stage"]) < STAGES.index(events[-1]["record"]["stage"]):
                raise CheckpointError("Checkpoint stage regression")
            return self._append(folder, job_id, events, "CHECKPOINT", record)

    def finalize_result(self, job_id: str, *, verify_persisted) -> dict:
        """Trusted host verifies result in external encrypted storage first.

        verify_persisted(ref, sha256, size) must independently check durable
        object presence, digest, owner/tenant scope and access permissions.
        Never call this directly from the sandbox or from an Android request.
        """
        with self._locked(job_id) as folder:
            events = self._read_events(folder, job_id)
            if not events:
                raise CheckpointError("No report checkpoint exists")
            last = events[-1]
            if last["event_type"] == "RESULT_COMMITTED":
                return last  # idempotent; chain already verified
            rec = last["record"]
            if rec["stage"] != "REPORT" or rec["status"] != "OK":
                raise CheckpointError("Cannot finalize without successful report")
            if not callable(verify_persisted) or verify_persisted(
                rec["artifact_ref"], rec["artifact_sha256"], rec["artifact_bytes"]
            ) is not True:
                raise CheckpointError("Durable result verification failed")
            final = {
                "result_ref": rec["artifact_ref"], "result_sha256": rec["artifact_sha256"],
                "result_bytes": rec["artifact_bytes"],
                "report_checkpoint_sha256": last["event_sha256"],
            }
            return self._append(folder, job_id, events, "RESULT_COMMITTED", final)

    def cleanup_receipt(self, job_id: str) -> tuple[str, str]:
        """For trusted WorkspaceStore.result_persisted after final integrity check.

        Does NOT itself call workspace cleanup: A5 must verify the external
        object and tenant ownership again before authorizing data deletion.
        """
        state = self.inspect(job_id)
        if not state["final"]:
            raise CheckpointError("No persisted final result")
        item = state["events"][-1]["record"]
        return item["result_sha256"], item["result_ref"]

    def user_progress(self, job_id: str) -> dict:
        """No paths, object refs, secret-bearing output or internal provenance."""
        report = self.inspect(job_id)
        steps = []
        for event in report["events"]:
            if event["event_type"] != "CHECKPOINT":
                continue
            rec = event["record"]
            steps.append({
                "stage": rec["stage"], "status": rec["status"],
                "evidence": rec["evidence"], "error_code": rec["error_code"],
                "output_available": rec["artifact_ref"] is not None,
            })
        return {"schema_version": 1, "completed": report["final"], "steps": steps}

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from tempfile import NamedTemporaryFile
from typing import Any

PROJECT_DIR = Path(__file__).resolve().parent.parent
CONFIG_PATH = PROJECT_DIR / "config.json"
DECODERS_PATH = PROJECT_DIR / "decoders.json"
DEFAULT_ADMIN_ID = 5325631223


@dataclass(frozen=True, slots=True)
class AppConfig:
    token: str
    admins: frozenset[int]
    allowed_groups: frozenset[int]
    allow_all_groups: bool
    downloads_dir: Path
    results_dir: Path
    decoder_timeout_seconds: int
    max_file_size_bytes: int
    text_session_timeout_seconds: int
    text_session_max_chars: int
    allowed_private_users: frozenset[int] = frozenset()
    # Groups the bot is in (id -> title), remembered from received activity.
    known_groups: dict[int, str] = field(default_factory=dict)

    @property
    def ssc_session_timeout_seconds(self) -> int:
        """Legacy alias for older configurations."""
        return self.text_session_timeout_seconds

    @property
    def ssc_max_text_chars(self) -> int:
        """Legacy alias for older configurations."""
        return self.text_session_max_chars

    @property
    def max_file_size_mb(self) -> int:
        return self.max_file_size_bytes // (1024 * 1024)


def _normalize_id_list(value: Any, field_name: str) -> frozenset[int]:
    if value is None:
        return frozenset()
    if not isinstance(value, list):
        raise ValueError(f"'{field_name}' must be a list of numeric IDs.")

    normalized: set[int] = set()
    for item in value:
        if isinstance(item, bool):
            raise ValueError(f"Invalid ID in '{field_name}': {item!r}")
        try:
            normalized.add(int(item))
        except (TypeError, ValueError) as exc:
            raise ValueError(f"Invalid ID in '{field_name}': {item!r}") from exc
    return frozenset(normalized)


def _normalize_bool(value: Any, field_name: str) -> bool:
    if isinstance(value, bool):
        return value
    if value in (None, 0, "0", "false", "False", "no", "No", ""):
        return False
    if value in (1, "1", "true", "True", "yes", "Yes"):
        return True
    raise ValueError(f"'{field_name}' must be true or false.")


def _normalize_known_groups(value: Any) -> dict[int, str]:
    """Normalize the remembered group list; malformed entries are dropped."""
    if not isinstance(value, dict):
        return {}
    normalized: dict[int, str] = {}
    for raw_id, raw_title in value.items():
        try:
            chat_id = int(raw_id)
        except (TypeError, ValueError):
            continue
        if chat_id >= 0:
            continue
        normalized[chat_id] = " ".join(str(raw_title or "").split())
    return normalized


def _resolve_project_path(value: Any, default: str) -> Path:
    raw = str(value or default).strip()
    path = Path(raw).expanduser()
    return path.resolve() if path.is_absolute() else (PROJECT_DIR / path).resolve()


def load_config(path: Path = CONFIG_PATH) -> AppConfig:
    """Load and validate config.json, including legacy configuration files."""
    if not path.exists():
        raise FileNotFoundError(
            f"Could not find {path.name}. Copy config.example.json and configure the bot."
        )

    with path.open("r", encoding="utf-8") as config_file:
        data = json.load(config_file)

    if not isinstance(data, dict):
        raise ValueError("config.json must contain a JSON object at its root.")

    bot_config = data.get("bot", {})
    access_config = data.get("access", {})
    runtime_config = data.get("runtime", {})

    if not isinstance(bot_config, dict):
        raise ValueError("'bot' must be a JSON object.")
    if not isinstance(access_config, dict):
        raise ValueError("'access' must be a JSON object.")
    if not isinstance(runtime_config, dict):
        raise ValueError("'runtime' must be a JSON object.")

    token = (
        os.getenv("SPDECODE_BOT_TOKEN")
        or bot_config.get("token")
        or data.get("TOKEN")
    )
    legacy_private_admin = data.get("chat_privado_especial_id")
    default_admins = [DEFAULT_ADMIN_ID] if legacy_private_admin is None else []
    admins = list(access_config.get("admins", data.get("admins", default_admins)) or [])
    allowed_groups = access_config.get(
        "allowed_groups", data.get("grupos_permitidos_ids", [])
    )
    group_ids = _normalize_id_list(allowed_groups, "access.allowed_groups")
    if "allowed_private_users" in access_config:
        private_ids = _normalize_id_list(access_config["allowed_private_users"], "access.allowed_private_users")
    else:
        # Older configs could authorize private chats via positive IDs.
        private_ids = group_ids
    allow_all_groups = _normalize_bool(
        access_config.get("allow_all_groups", False),
        "access.allow_all_groups",
    )
    known_groups = _normalize_known_groups(access_config.get("known_groups", {}))

    if legacy_private_admin is not None and legacy_private_admin not in admins:
        admins.append(legacy_private_admin)

    if not isinstance(token, str) or not token.strip():
        raise ValueError(
            "Set 'bot.token' in config.json or the SPDECODE_BOT_TOKEN environment variable."
        )
    if token.strip() == "PUT_YOUR_TELEGRAM_BOT_TOKEN_HERE":
        raise ValueError(
            "Replace the example token or set SPDECODE_BOT_TOKEN before starting."
        )

    try:
        timeout = int(runtime_config.get("decoder_timeout_seconds", 90))
        max_file_size_mb = int(runtime_config.get("max_file_size_mb", 25))
        text_session_timeout_seconds = int(
            runtime_config.get(
                "text_session_timeout_seconds",
                runtime_config.get("ssc_session_timeout_seconds", 600),
            )
        )
        text_session_max_chars = int(
            runtime_config.get(
                "text_session_max_chars",
                runtime_config.get("ssc_max_text_chars", 250000),
            )
        )
    except (TypeError, ValueError) as exc:
        raise ValueError("'runtime' values must be numeric.") from exc

    if timeout < 1:
        raise ValueError("'runtime.decoder_timeout_seconds' must be greater than zero.")
    if max_file_size_mb < 1:
        raise ValueError("'runtime.max_file_size_mb' must be greater than zero.")
    if text_session_timeout_seconds < 30:
        raise ValueError("'runtime.text_session_timeout_seconds' must be at least 30.")
    if text_session_max_chars < 4096:
        raise ValueError("'runtime.text_session_max_chars' must be at least 4096.")

    return AppConfig(
        token=token.strip(),
        admins=_normalize_id_list(admins, "access.admins"),
        allowed_groups=frozenset(value for value in group_ids if value < 0),
        allowed_private_users=frozenset(value for value in private_ids if value > 0),
        allow_all_groups=allow_all_groups,
        known_groups=known_groups,
        downloads_dir=_resolve_project_path(runtime_config.get("downloads_dir"), "Downloads"),
        results_dir=_resolve_project_path(runtime_config.get("results_dir"), "Results"),
        decoder_timeout_seconds=timeout,
        max_file_size_bytes=max_file_size_mb * 1024 * 1024,
        text_session_timeout_seconds=text_session_timeout_seconds,
        text_session_max_chars=text_session_max_chars,
    )



def save_chat_permissions(config: AppConfig, path: Path = CONFIG_PATH) -> None:
    """Atomically persist managed chat permissions and preserve other settings."""
    path = path.resolve(strict=True)
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict) or not isinstance(data.get("access", {}), dict):
        raise ValueError("The access configuration must be a JSON object.")

    access = data.setdefault("access", {})
    access["allow_all_groups"] = config.allow_all_groups
    access["allowed_groups"] = sorted(config.allowed_groups)
    access["allowed_private_users"] = sorted(config.allowed_private_users)
    access["known_groups"] = {
        str(chat_id): title for chat_id, title in sorted(config.known_groups.items())
    }
    temporary: Path | None = None
    try:
        # NamedTemporaryFile creates a mode-0600 file containing existing secrets.
        with NamedTemporaryFile("w", encoding="utf-8", dir=path.parent, prefix=".access-", delete=False) as stream:
            temporary = Path(stream.name)
            json.dump(data, stream, indent=4, ensure_ascii=False)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)

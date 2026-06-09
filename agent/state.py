from __future__ import annotations

import json
import os
import platform
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping


STATE_FILE_NAME = "agent_state.json"


class AgentStateError(ValueError):
    """Raised when protected agent state cannot satisfy runtime policy."""


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def default_state_dir() -> Path:
    override = os.getenv("INSIEDR_STATE_DIR")
    if override:
        return Path(override).expanduser()
    if platform.system() == "Windows":
        base = os.getenv("PROGRAMDATA")
        if base:
            return Path(base) / "InsiEDR"
    return Path.home() / ".local" / "state" / "insiedr"


def ensure_protected_dir(path: str | Path) -> Path:
    state_dir = Path(path).expanduser()
    state_dir.mkdir(parents=True, exist_ok=True)
    chmod_restrictive(state_dir, 0o700)
    return state_dir


def chmod_restrictive(path: str | Path, mode: int) -> None:
    if os.name == "nt":
        return
    try:
        os.chmod(path, mode)
    except OSError:
        pass


def read_json_file(path: str | Path) -> dict[str, Any]:
    with Path(path).open("r", encoding="utf-8") as fh:
        data = json.load(fh)
    if not isinstance(data, dict):
        raise AgentStateError(f"{Path(path).name} must contain a JSON object")
    return data


def write_json_file(path: str | Path, data: Mapping[str, Any]) -> None:
    final_path = Path(path)
    ensure_protected_dir(final_path.parent)
    tmp_path = final_path.with_suffix(final_path.suffix + ".tmp")
    with tmp_path.open("w", encoding="utf-8") as fh:
        json.dump(dict(data), fh, sort_keys=True, indent=2)
        fh.write("\n")
    chmod_restrictive(tmp_path, 0o600)
    tmp_path.replace(final_path)
    chmod_restrictive(final_path, 0o600)


def agent_state_path(state_dir: str | Path | None = None) -> Path:
    return ensure_protected_dir(state_dir or default_state_dir()) / STATE_FILE_NAME


def _new_agent_id(hostname: str, enrollment_id: str | None) -> str:
    if enrollment_id:
        return str(uuid.uuid5(uuid.NAMESPACE_URL, f"insiedr-agent:{enrollment_id}"))
    return f"{hostname}-{uuid.uuid4()}"


def load_or_create_agent_id(
    *,
    hostname: str,
    state_dir: str | Path | None = None,
    configured_agent_id: str | None = None,
    enrollment_id: str | None = None,
    mode: str = "production",
) -> str:
    path = agent_state_path(state_dir)
    production = mode.strip().lower() == "production"

    if path.exists():
        state = read_json_file(path)
        agent_id = state.get("agent_id")
        if not isinstance(agent_id, str) or not agent_id:
            raise AgentStateError(f"{path} is missing agent_id")
        if configured_agent_id and configured_agent_id != agent_id:
            raise AgentStateError(
                "configured agent identity does not match the protected state file"
            )
        return agent_id

    if production and not configured_agent_id and not enrollment_id:
        raise AgentStateError(
            "production agent identity requires INSIEDR_AGENT_ID or INSIEDR_ENROLLMENT_ID"
        )

    agent_id = configured_agent_id or _new_agent_id(hostname, enrollment_id)
    write_json_file(
        path,
        {
            "agent_id": agent_id,
            "created_at": utc_now_iso(),
            "identity_source": (
                "configured_agent_id"
                if configured_agent_id
                else "enrollment_id"
                if enrollment_id
                else "generated_non_production"
            ),
        },
    )
    return agent_id


def protected_state_file(name: str, *, state_dir: str | Path | None = None) -> Path:
    if Path(name).name != name:
        raise AgentStateError("state file names must not include directories")
    return ensure_protected_dir(state_dir or default_state_dir()) / name

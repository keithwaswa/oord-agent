from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Optional

import tomllib


@dataclass
class CoreConfig:
    base_url: str


@dataclass
class OrgConfig:
    id: str
    batch_prefix: Optional[str] = None


@dataclass
class AgentSection:
    poll_interval_sec: int = 2
    settle_seconds: int = 5
    recursive: bool = True


@dataclass
class SenderPaths:
    watch_dir: Path
    out_dir: Path
    state_file: Path


@dataclass
class ReceiverPaths:
    incoming_dir: Path
    verified_root: Path
    quarantine_dir: Path
    state_file: Path


@dataclass
class AgentConfig:
    mode: str  # "sender" | "receiver"
    core: CoreConfig
    org: OrgConfig
    agent: AgentSection
    sender_paths: Optional[SenderPaths] = None
    receiver_paths: Optional[ReceiverPaths] = None


def _require_section(cfg: dict, name: str) -> dict:
    section = cfg.get(name)
    if not isinstance(section, dict):
        raise ValueError(f"config: missing or invalid [{name}] section")
    return section


def _require_str(d: dict, key: str) -> str:
    v = d.get(key)
    if not isinstance(v, str) or not v:
        raise ValueError(f"config: missing or invalid {key!r}")
    return v


def _optional_str(d: dict, key: str) -> Optional[str]:
    v = d.get(key)
    if v is None:
        return None
    if not isinstance(v, str):
        raise ValueError(f"config: {key!r} must be a string if set")
    return v


def _require_int(d: dict, key: str, default: Optional[int] = None) -> int:
    if key not in d:
        if default is None:
            raise ValueError(f"config: missing {key!r}")
        return default
    v = d[key]
    if not isinstance(v, int):
        raise ValueError(f"config: {key!r} must be an integer")
    return v


def _require_bool(d: dict, key: str, default: Optional[bool] = None) -> bool:
    if key not in d:
        if default is None:
            raise ValueError(f"config: missing {key!r}")
        return default
    v = d[key]
    if not isinstance(v, bool):
        raise ValueError(f"config: {key!r} must be a boolean")
    return v


def load_config(path: Path) -> AgentConfig:
    if not path.is_file():
        raise FileNotFoundError(f"config file not found: {path}")
    raw = path.read_bytes()
    cfg = tomllib.loads(raw.decode("utf-8"))

    mode = cfg.get("mode")
    if mode not in ("sender", "receiver"):
        raise ValueError("config: mode must be 'sender' or 'receiver'")

    core_section = _require_section(cfg, "core")
    org_section = _require_section(cfg, "org")
    agent_section = cfg.get("agent") or {}

    core = CoreConfig(base_url=_require_str(core_section, "base_url"))
    org = OrgConfig(
        id=_require_str(org_section, "id"),
        batch_prefix=_optional_str(org_section, "batch_prefix"),
    )

    agent_cfg = AgentSection(
        poll_interval_sec=_require_int(agent_section, "poll_interval_sec", default=1),
        settle_seconds=_require_int(agent_section, "settle_seconds", default=2),
        recursive=_require_bool(agent_section, "recursive", default=True),
    )

    sender_paths: Optional[SenderPaths] = None
    receiver_paths: Optional[ReceiverPaths] = None

    if mode == "sender":
        sender_section = cfg.get("sender")
        if not isinstance(sender_section, dict):
            raise ValueError("config: missing [sender] section for sender mode")
        paths_section = sender_section.get("paths")
        if not isinstance(paths_section, dict):
            raise ValueError("config: missing [sender.paths] section for sender mode")

        watch_dir = Path(_require_str(paths_section, "watch_dir")).expanduser()
        out_dir = Path(_require_str(paths_section, "out_dir")).expanduser()
        state_file = Path(_require_str(paths_section, "state_file")).expanduser()
        sender_paths = SenderPaths(
            watch_dir=watch_dir,
            out_dir=out_dir,
            state_file=state_file,
        )

    if mode == "receiver":
        receiver_section = cfg.get("receiver")
        if not isinstance(receiver_section, dict):
            raise ValueError("config: missing [receiver] section for receiver mode")
        paths_section = receiver_section.get("paths")
        if not isinstance(paths_section, dict):
            raise ValueError("config: missing [receiver.paths] section for receiver mode")

        incoming_dir = Path(_require_str(paths_section, "incoming_dir")).expanduser()
        verified_root = Path(_require_str(paths_section, "verified_root")).expanduser()
        quarantine_dir = Path(_require_str(paths_section, "quarantine_dir")).expanduser()
        state_file = Path(_require_str(paths_section, "state_file")).expanduser()
        receiver_paths = ReceiverPaths(
            incoming_dir=incoming_dir,
            verified_root=verified_root,
            quarantine_dir=quarantine_dir,
            state_file=state_file,
        )

    return AgentConfig(
        mode=mode,
        core=core,
        org=org,
        agent=agent_cfg,
        sender_paths=sender_paths,
        receiver_paths=receiver_paths,
    )

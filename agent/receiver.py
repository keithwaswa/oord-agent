# agent/receiver.py
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import time
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Tuple

from .config import AgentConfig


@dataclass
class ReceiverState:
    processed_bundles: Dict[str, str]


def load_state(path: Path) -> ReceiverState:
    if not path.is_file():
        return ReceiverState(processed_bundles={})
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return ReceiverState(processed_bundles={})
    processed = data.get("processed_bundles") or {}
    if not isinstance(processed, dict):
        processed = {}
    processed_str: Dict[str, str] = {}
    for k, v in processed.items():
        if isinstance(k, str) and isinstance(v, str):
            processed_str[k] = v
    return ReceiverState(processed_bundles=processed_str)


def save_state(path: Path, state: ReceiverState) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    data = {"processed_bundles": state.processed_bundles}
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(data, sort_keys=True, indent=2), encoding="utf-8")
    tmp.replace(path)


def _latest_mtime_file(p: Path) -> float:
    return p.stat().st_mtime


def is_bundle_stable(bundle_path: Path, settle_seconds: int, now: float | None = None) -> bool:
    if now is None:
        now = time.time()
    latest = _latest_mtime_file(bundle_path)
    return (now - latest) >= settle_seconds


def find_ready_bundles(
    incoming_dir: Path,
    state: ReceiverState,
    settle_seconds: int,
    now: float | None = None,
) -> List[Path]:
    """
    One bundle = one file matching oord_bundle_*.zip in incoming_dir.
    """
    ready: List[Path] = []
    processed = state.processed_bundles
    if not incoming_dir.is_dir():
        return ready

    for child in sorted(incoming_dir.iterdir()):
        if not child.is_file():
            continue
        name = child.name
        if not name.startswith("oord_bundle_") or not name.endswith(".zip"):
            continue
        if processed.get(name) in ("verified", "quarantined"):
            continue
        if not is_bundle_stable(child, settle_seconds=settle_seconds, now=now):
            continue
        ready.append(child)
    return ready


def verify_bundle_via_cli(cfg: AgentConfig, bundle_path: Path) -> Tuple[int, str, str]:
    """
    Call the Oord CLI as a subprocess to verify a bundle.

    Returns: (exit_code, stdout, stderr)
    """
    cmd = [
        sys.executable,
        "-m",
        "cli.oord_cli",
        "verify",
        str(bundle_path),
    ]
    proc = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
    )
    return proc.returncode, proc.stdout, proc.stderr


def _extract_verified_files(bundle_path: Path, dest_root: Path) -> None:
    dest_dir = dest_root / bundle_path.stem
    dest_dir.mkdir(parents=True, exist_ok=True)

    with zipfile.ZipFile(bundle_path, "r") as z:
        for name in z.namelist():
            if not name.startswith("files/"):
                continue
            rel = name[len("files/") :]
            if not rel:
                continue
            out_path = dest_dir / rel
            out_path.parent.mkdir(parents=True, exist_ok=True)
            with z.open(name, "r") as src, open(out_path, "wb") as dst:
                shutil.copyfileobj(src, dst)


def run_receiver_loop(cfg: AgentConfig, once: bool = False) -> None:
    if cfg.receiver_paths is None:
        raise RuntimeError("receiver mode requires receiver_paths in config")

    incoming_dir = cfg.receiver_paths.incoming_dir
    verified_root = cfg.receiver_paths.verified_root
    quarantine_dir = cfg.receiver_paths.quarantine_dir
    state_path = cfg.receiver_paths.state_file

    state = load_state(state_path)

    while True:
        now = time.time()
        ready = find_ready_bundles(
            incoming_dir=incoming_dir,
            state=state,
            settle_seconds=cfg.agent.settle_seconds,
            now=now,
        )

        for bundle_path in ready:
            code, stdout, stderr = verify_bundle_via_cli(cfg, bundle_path)
            if stdout:
                print(stdout.strip())
            if stderr:
                print(stderr.strip(), file=sys.stderr)

            name = bundle_path.name

            if code == 0:
                # verified; extract files and record state
                _extract_verified_files(bundle_path, verified_root)
                state.processed_bundles[name] = "verified"
                save_state(state_path, state)
            elif code == 1:
                # verification failure; move to quarantine
                quarantine_dir.mkdir(parents=True, exist_ok=True)
                target = quarantine_dir / name
                os.replace(bundle_path, target)
                state.processed_bundles[name] = "quarantined"
                save_state(state_path, state)
            else:
                # env/usage error (exit code 2 etc.) – leave bundle in place, do not mark state
                continue

        if once:
            # Dev/one-shot mode: process whatever was ready and exit.
            break

        time.sleep(cfg.agent.poll_interval_sec)


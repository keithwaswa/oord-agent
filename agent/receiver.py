# agent/receiver.py
from __future__ import annotations

import datetime
import json
import logging
import os
import shutil
import subprocess
import sys
import time
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from .config import AgentConfig


logger = logging.getLogger("agent.receiver")


def _log(level: str, event: str, **fields: object) -> None:
    """
    Structured-ish logging helper for receiver events.
    Emits lines like:
      [receiver] 2025-... level=INFO event=verify_pass bundle=...
    """
    ts = datetime.datetime.now(datetime.UTC).isoformat(timespec="seconds") + "Z"
    parts = [f"event={event}"]
    for k, v in fields.items():
        parts.append(f"{k}={v}")
    msg = f"[receiver] {ts} level={level.upper()} " + " ".join(parts)
    if level.lower() == "error":
        logger.error(msg)
    elif level.lower() == "warning":
        logger.warning(msg)
    else:
        logger.info(msg)

@dataclass
class ReceiverBundleStatus:
    status: str  # "verified" | "quarantined" | "retry"
    attempts: int = 0
    next_retry_at_ms: int = 0
    last_exit_code: Optional[int] = None
    last_error: Optional[str] = None


@dataclass
class ReceiverState:
    bundles: Dict[str, ReceiverBundleStatus]



def load_state(path: Path) -> ReceiverState:
    if not path.is_file():
        return ReceiverState(bundles={})
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
            return ReceiverState(bundles={})

    raw = data.get("bundles") or {}
    if not isinstance(raw, dict):
        return ReceiverState(bundles={})

    out: Dict[str, ReceiverBundleStatus] = {}
    for name, v in raw.items():
        if not isinstance(name, str) or not isinstance(v, dict):
            continue
        status = v.get("status")
        if status not in ("verified", "quarantined", "retry"):
            continue
        attempts = v.get("attempts")
        next_retry_at_ms = v.get("next_retry_at_ms")
        last_exit_code = v.get("last_exit_code")
        last_error = v.get("last_error")

        out[name] = ReceiverBundleStatus(
            status=status,
            attempts=int(attempts) if isinstance(attempts, int) and attempts >= 0 else 0,
            next_retry_at_ms=int(next_retry_at_ms) if isinstance(next_retry_at_ms, int) and next_retry_at_ms >= 0 else 0,
            last_exit_code=int(last_exit_code) if isinstance(last_exit_code, int) else None,
            last_error=str(last_error) if isinstance(last_error, str) else None,
        )

    return ReceiverState(bundles=out)



def save_state(path: Path, state: ReceiverState) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    data = {
        "bundles": {
            name: {
                "status": s.status,
                "attempts": s.attempts,
                "next_retry_at_ms": s.next_retry_at_ms,
                "last_exit_code": s.last_exit_code,
                "last_error": s.last_error,
            }
            for name, s in state.bundles.items()
        }
    }
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(data, sort_keys=True, indent=2), encoding="utf-8")
    tmp.replace(path)


def _latest_mtime_file(p: Path) -> float:
    return p.stat().st_mtime

def _compute_backoff_ms(attempts: int) -> int:
    base = 500
    cap = 60_000
    exp = min(cap, base * (2 ** max(0, attempts - 1)))
    jitter = int((time.time() * 1000) % 250)
    return min(cap, exp + jitter)

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
    if not incoming_dir.is_dir():
        return ready
    
    now_ms = int((now if now is not None else time.time()) * 1000)

    for child in sorted(incoming_dir.iterdir()):
        if not child.is_file():
            continue
        name = child.name
        if not name.startswith("oord_bundle_") or not name.endswith(".zip"):
            continue
        st = state.bundles.get(name)
        if st and st.status in ("verified", "quarantined"):
            continue
        if st and st.next_retry_at_ms and now_ms < st.next_retry_at_ms:
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
    _log("info", "verify_start", bundle=str(bundle_path))

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

def _safe_path_part(s: str) -> str:
    s = s.strip()
    if not s:
        return "-"
    # conservative: keep alnum, dash, underscore, dot; turn everything else into "_"
    out = []
    for ch in s:
        if ch.isalnum() or ch in ("-", "_", "."):
            out.append(ch)
        else:
            out.append("_")
    return "".join(out)


def _extract_dir_for_bundle(bundle_path: Path, z: zipfile.ZipFile, verified_root: Path) -> Path:
    """
    Extraction contract:
      verified_root/<org_id>/<batch_id>/<bundle_stem>/...

    Falls back to verified_root/<bundle_stem>/... if manifest is missing/bad.
    """
    try:
        raw = z.read("manifest.json").decode("utf-8")
        obj = json.loads(raw)
        if isinstance(obj, dict):
            org_id = obj.get("org_id")
            batch_id = obj.get("batch_id")
            if isinstance(org_id, str) and isinstance(batch_id, str):
                return verified_root / _safe_path_part(org_id) / _safe_path_part(batch_id) / bundle_path.stem
    except Exception:
        pass
    return verified_root / bundle_path.stem

def _extract_verified_files(bundle_path: Path, dest_root: Path) -> Path:
    with zipfile.ZipFile(bundle_path, "r") as z:
        final_dir = _extract_dir_for_bundle(bundle_path, z, dest_root)
        tmp_dir = final_dir.with_name(final_dir.name + ".tmp")

        if tmp_dir.exists():
            shutil.rmtree(tmp_dir)
        tmp_dir.mkdir(parents=True, exist_ok=True)

        for name in z.namelist():
            if not name.startswith("files/"):
                continue
            rel = name[len("files/") :]
            if not rel:
                continue
            out_path = tmp_dir / rel
            out_path.parent.mkdir(parents=True, exist_ok=True)
            with z.open(name, "r") as src, open(out_path, "wb") as dst:
                shutil.copyfileobj(src, dst)
    
        if final_dir.exists():
            shutil.rmtree(final_dir)
        tmp_dir.replace(final_dir)
        return final_dir



def run_receiver_loop(cfg: AgentConfig, once: bool = False) -> None:
    if cfg.receiver_paths is None:
        raise RuntimeError("receiver mode requires receiver_paths in config")

    incoming_dir = cfg.receiver_paths.incoming_dir
    verified_root = cfg.receiver_paths.verified_root
    quarantine_dir = cfg.receiver_paths.quarantine_dir
    state_path = cfg.receiver_paths.state_file

    _log(
        "info",
        "agent_start",
        incoming_dir=str(incoming_dir),
        verified_root=str(verified_root),
        quarantine_dir=str(quarantine_dir),
        state_file=str(state_path),
        poll_interval_sec=cfg.agent.poll_interval_sec,
        settle_seconds=cfg.agent.settle_seconds,
    )

    state = load_state(state_path)

    while True:
        now = time.time()
        ready = find_ready_bundles(
            incoming_dir=incoming_dir,
            state=state,
            settle_seconds=cfg.agent.settle_seconds,
            now=now,
        )

        if ready:
            _log(
                "info",
                "bundles_ready",
                count=len(ready),
                incoming_dir=str(incoming_dir),
            )


        for bundle_path in ready:
            code, stdout, stderr = verify_bundle_via_cli(cfg, bundle_path)
            if stdout:
                # passthrough CLI stdout
                print(stdout.strip())
            if stderr:
                # passthrough CLI stderr
                print(stderr.strip(), file=sys.stderr)

            name = bundle_path.name

            if code == 0:
                # verified; extract files and record state
                dest_dir = _extract_verified_files(bundle_path, verified_root)
                _log(
                    "info",
                    "verify_pass",
                    bundle=name,
                    extracted_to=str(dest_dir),
                )
                prev = state.bundles.get(name)
                state.bundles[name] = ReceiverBundleStatus(
                    status="verified",
                    attempts=prev.attempts if prev else 0,
                )
                save_state(state_path, state)
            elif code == 1:
                # verification failure; move to quarantine
                quarantine_dir.mkdir(parents=True, exist_ok=True)
                target = quarantine_dir / name
                os.replace(bundle_path, target)
                _log(
                    "warning",
                    "verify_fail",
                    bundle=name,
                    moved_to_quarantine=str(target),
                    exit_code=code,
                )
                prev = state.bundles.get(name)
                state.bundles[name] = ReceiverBundleStatus(
                    status="quarantined",
                    attempts=prev.attempts if prev else 0,
                    last_exit_code=1,
                )
                save_state(state_path, state)
            else:
                # env/usage error (exit code 2 etc.) – leave bundle in place, do not mark state
                entry = state.bundles.get(name) or ReceiverBundleStatus(status="retry")
                entry.status = "retry"
                entry.attempts = entry.attempts + 1
                entry.last_exit_code = int(code)
                entry.last_error = (stderr.strip() if stderr else None) or (stdout.strip() if stdout else None)
                backoff_ms = _compute_backoff_ms(entry.attempts)
                entry.next_retry_at_ms = int(time.time() * 1000) + backoff_ms
                state.bundles[name] = entry
                save_state(state_path, state)
                _log(
                    "error",
                    "verify_env_error",
                    bundle=name,
                    exit_code=code,
                    next_retry_in_ms=backoff_ms,
                )
                continue

        if once:
            # Dev/one-shot mode: process whatever was ready and exit.
            _log("info", "agent_exit", reason="once_mode")
            break

        time.sleep(cfg.agent.poll_interval_sec)

    _log("info", "agent_exit", reason="loop_ended")


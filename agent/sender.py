# agent/sender.py
from __future__ import annotations

import datetime
import json
import logging
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Tuple, Optional

from .config import AgentConfig


logger = logging.getLogger("agent.sender")


def _log(level: str, event: str, **fields: object) -> None:
    """
    Structured-ish logging helper for sender events.
    Emits lines like:
      [sender] 2025-... level=INFO event=seal_start batch=B001 ...
    """
    ts = datetime.datetime.now(datetime.UTC).isoformat(timespec="seconds") + "Z"
    parts = [f"event={event}"]
    for k, v in fields.items():
        parts.append(f"{k}={v}")
    msg = f"[sender] {ts} level={level.upper()} " + " ".join(parts)
    if level.lower() == "error":
        logger.error(msg)
    elif level.lower() == "warning":
        logger.warning(msg)
    else:
        logger.info(msg)

@dataclass
class SenderBatchStatus:
    status: str  # "sealed" | "retry"
    attempts: int = 0
    next_retry_at_ms: int = 0
    last_exit_code: Optional[int] = None
    last_error: Optional[str] = None

@dataclass
class SenderState:
    batches: Dict[str, SenderBatchStatus]


def load_state(path: Path) -> SenderState:
    if not path.is_file():
        return SenderState(batches={})
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return SenderState(batches={})

    raw = data.get("batches") or {}
    if not isinstance(raw, dict):
        return SenderState(batches={})

    out: Dict[str, SenderBatchStatus] = {}
    for name, v in raw.items():
        if not isinstance(name, str) or not isinstance(v, dict):
            continue
        status = v.get("status")
        if status not in ("sealed", "retry"):
            continue
        attempts = v.get("attempts")
        next_retry_at_ms = v.get("next_retry_at_ms")
        last_exit_code = v.get("last_exit_code")
        last_error = v.get("last_error")

        out[name] = SenderBatchStatus(
            status=status,
            attempts=int(attempts) if isinstance(attempts, int) and attempts >= 0 else 0,
            next_retry_at_ms=int(next_retry_at_ms) if isinstance(next_retry_at_ms, int) and next_retry_at_ms >= 0 else 0,
            last_exit_code=int(last_exit_code) if isinstance(last_exit_code, int) else None,
            last_error=str(last_error) if isinstance(last_error, str) else None,
        )

    return SenderState(batches=out)


def save_state(path: Path, state: SenderState) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    data = {
        "batches": {
            name: {
                "status": s.status,
                "attempts": s.attempts,
                "next_retry_at_ms": s.next_retry_at_ms,
                "last_exit_code": s.last_exit_code,
                "last_error": s.last_error,
            }
            for name, s in state.batches.items()
        }
    }
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(data, sort_keys=True, indent=2), encoding="utf-8")
    tmp.replace(path)


def _latest_mtime(p: Path) -> float:
    latest = p.stat().st_mtime
    for child in p.rglob("*"):
        try:
            st = child.stat()
        except FileNotFoundError:
            continue
        if st.st_mtime > latest:
            latest = st.st_mtime
    return latest


def is_folder_stable(folder: Path, settle_seconds: int, now: float | None = None) -> bool:
    if now is None:
        now = time.time()
    latest = _latest_mtime(folder)
    return (now - latest) >= settle_seconds

def _compute_backoff_ms(attempts: int) -> int:
    base = 500
    cap = 60_000
    exp = min(cap, base * (2 ** max(0, attempts - 1)))
    jitter = int((time.time() * 1000) % 250)
    return min(cap, exp + jitter)


def find_ready_batches(
    watch_dir: Path,
    state: SenderState,
    settle_seconds: int,
    now: float | None = None,
) -> List[Path]:
    """
    One batch = one immediate subfolder of watch_dir.

    Returns a list of batch directories that:
      - are not marked 'sealed' in state
      - have not changed in the last settle_seconds
    """
    ready: List[Path] = []
    if not watch_dir.is_dir():
        return ready
    
    now_ms = int((now if now is not None else time.time()) * 1000)

    for child in sorted(watch_dir.iterdir()):
        if not child.is_dir():
            continue
        name = child.name
        st = state.batches.get(name)
        if st and st.status == "sealed":
            continue
        if st and st.next_retry_at_ms and now_ms < st.next_retry_at_ms:
            continue
        if not is_folder_stable(child, settle_seconds=settle_seconds, now=now):
            continue
        ready.append(child)
    return ready


def _compute_batch_id(batch_dir: Path, prefix: str | None) -> str:
    name = batch_dir.name
    if prefix:
        return f"{prefix}-{name}"
    return name


def seal_batch_via_cli(
    cfg: AgentConfig,
    batch_dir: Path,
    out_dir: Path,
) -> Tuple[int, str, str]:
    """
    Call the Oord CLI as a subprocess to seal a batch directory.

    Returns: (exit_code, stdout, stderr)
    """
    batch_id = _compute_batch_id(batch_dir, cfg.org.batch_prefix)
    
    _log(
        "info",
        "seal_start",
        batch_name=batch_dir.name,
        batch_id=batch_id,
        input_dir=str(batch_dir),
        out_dir=str(out_dir),
    )

    cmd = [
        sys.executable,
        "-m",
        "cli.oord_cli",
        "seal",
        "--input-dir",
        str(batch_dir),
        "--out",
        str(out_dir),
        "--core-url",
        cfg.core.base_url,
        "--org-id",
        cfg.org.id,
        "--batch-id",
        batch_id,
    ]
    proc = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
    )
    return proc.returncode, proc.stdout, proc.stderr


def run_sender_loop(cfg: AgentConfig, once: bool = False) -> None:
    if cfg.sender_paths is None:
        raise RuntimeError("sender mode requires sender_paths in config")

    watch_dir = cfg.sender_paths.watch_dir
    out_dir = cfg.sender_paths.out_dir
    state_path = cfg.sender_paths.state_file

    _log(
        "info",
        "agent_start",
        watch_dir=str(watch_dir),
        out_dir=str(out_dir),
        state_file=str(state_path),
        poll_interval_sec=cfg.agent.poll_interval_sec,
        settle_seconds=cfg.agent.settle_seconds,
    )

    state = load_state(state_path)

    while True:
        now = time.time()
        ready_batches = find_ready_batches(
            watch_dir=watch_dir,
            state=state,
            settle_seconds=cfg.agent.settle_seconds,
            now=now,
        )

        if ready_batches:
            _log(
                "info",
                "batches_ready",
                count=len(ready_batches),
                watch_dir=str(watch_dir),
            )

        for batch_dir in ready_batches:
            code, stdout, stderr = seal_batch_via_cli(cfg, batch_dir, out_dir)
            if stdout:
                # passthrough CLI stdout for now
                print(stdout.strip())
            if stderr:
                # passthrough CLI stderr for now
                print(stderr.strip(), file=sys.stderr)

            name = batch_dir.name
            if code == 0:
                _log(
                    "info",
                    "seal_success",
                    batch_name=name,
                    batch_id=_compute_batch_id(batch_dir, cfg.org.batch_prefix),
                    out_dir=str(out_dir),
                    exit_code=code,
                )
                prev = state.batches.get(name)
                state.batches[name] = SenderBatchStatus(
                    status="sealed",
                    attempts=prev.attempts if prev else 0,
                    next_retry_at_ms=0,
                    last_exit_code=0,
                    last_error=None,
                )
                save_state(state_path, state)
            else:
                entry = state.batches.get(name) or SenderBatchStatus(status="retry")
                entry.status = "retry"
                entry.attempts = entry.attempts + 1
                entry.last_exit_code = int(code)
                entry.last_error = (stderr.strip() if stderr else None) or (stdout.strip() if stdout else None)
                backoff_ms = _compute_backoff_ms(entry.attempts)
                entry.next_retry_at_ms = int(time.time() * 1000) + backoff_ms
                state.batches[name] = entry
                save_state(state_path, state)

                _log(
                    "error",
                    "seal_failed",
                    batch_name=name,
                    batch_id=_compute_batch_id(batch_dir, cfg.org.batch_prefix),
                    out_dir=str(out_dir),
                    exit_code=code,
                    next_retry_in_ms=backoff_ms,
                )


        if once:
            # Dev/one-shot mode: process whatever was ready and exit.
            _log(
                "info",
                "agent_exit",
                reason="once_mode",
            )
            break

        time.sleep(cfg.agent.poll_interval_sec)

    _log("info", "agent_exit", reason="loop_ended")


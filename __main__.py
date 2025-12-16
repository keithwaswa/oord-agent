from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path
from typing import Optional

from agent.config import AgentConfig, load_config
from agent.receiver import run_receiver_loop
from agent.sender import run_sender_loop


def _setup_logging(level: str, log_file: Optional[Path] = None) -> None:
    """
    Configure process-wide logging.

    We keep the formatter simple and push all structure into the actual
    log lines emitted by sender/receiver helpers.
    """
    root = logging.getLogger()
    root.setLevel(level.upper())
    # avoid duplicate handlers if __main__ is invoked more than once in a process
    root.handlers.clear()

    formatter = logging.Formatter("%(message)s")

    stream_handler = logging.StreamHandler(sys.stdout)
    stream_handler.setFormatter(formatter)
    root.addHandler(stream_handler)

    if log_file is not None:
        log_file.parent.mkdir(parents=True, exist_ok=True)
        file_handler = logging.FileHandler(log_file, encoding="utf-8")
        file_handler.setFormatter(formatter)
        root.addHandler(file_handler)


def _parse_args(argv: Optional[list[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="agent",
        description="Oord Agent sender/receiver service entrypoint.",
    )

    subparsers = parser.add_subparsers(dest="command", required=True)

    def add_common(sp: argparse.ArgumentParser) -> None:
        sp.add_argument(
            "--config",
            required=True,
            help="Path to TOML config file.",
        )
        sp.add_argument(
            "--once",
            action="store_true",
            help="Run a single scan/iteration and then exit (dev/test).",
        )
        sp.add_argument(
            "--log-level",
            default=None,
            choices=["DEBUG", "INFO", "WARNING", "ERROR"],
            help="Override log level (default comes from config.logging.level or INFO).",
        )

    sender_sp = subparsers.add_parser("sender", help="Run the sender agent loop.")
    add_common(sender_sp)

    receiver_sp = subparsers.add_parser("receiver", help="Run the receiver agent loop.")
    add_common(receiver_sp)

    return parser.parse_args(argv)


def main(argv: Optional[list[str]] = None) -> None:
    args = _parse_args(argv)

    cfg_path = Path(args.config).expanduser()
    cfg: AgentConfig = load_config(cfg_path)

    # Sanity check: mode in config should match the invoked command.
    if cfg.mode != args.command:
        raise SystemExit(
            f"config mode mismatch: config.mode={cfg.mode!r} but invoked command={args.command!r}"
        )

    once = bool(getattr(args, "once", False))
    # Determine log level and optional file from config + CLI override.
    log_level = args.log_level or cfg.logging.level or "INFO"
    log_file = cfg.logging.file

    _setup_logging(level=log_level, log_file=log_file)

    # Emit a simple startup line; sender/receiver will emit more detailed ones.
    import datetime

    ts = datetime.datetime.utcnow().isoformat(timespec="seconds") + "Z"
    logging.getLogger("agent").info(
        f"[{cfg.mode}] {ts} level=INFO event=agent_entrypoint "
        f"config_path={cfg_path} log_level={log_level}"
    )

    if args.command == "sender":
        run_sender_loop(cfg, once=once)
    elif args.command == "receiver":
        run_receiver_loop(cfg, once=once)
    else:
        # argparse should prevent this, but keep a guard.
        raise SystemExit(f"unknown command: {args.command!r}")


if __name__ == "__main__":
    main()

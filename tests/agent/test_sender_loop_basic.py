# tests/agent/test_sender_loop_basic.py
import logging
import json
from pathlib import Path
from types import SimpleNamespace

import agent.sender as sender
from agent.config import AgentConfig, CoreConfig, OrgConfig, AgentSection, SenderPaths, LoggingConfig

def make_cfg(tmp_path):
    return AgentConfig(
        mode="sender",
        core=CoreConfig(base_url="http://core"),
        org=OrgConfig(id="ORG", batch_prefix="PX"),
        agent=AgentSection(poll_interval_sec=1, settle_seconds=0),
        logging=LoggingConfig(level="INFO"),
        sender_paths=SenderPaths(
            watch_dir=tmp_path / "watch",
            out_dir=tmp_path / "out",
            state_file=tmp_path / "state.json",
        ),
        receiver_paths=None,
    )

def test_sender_loop_seals_one_batch(tmp_path, monkeypatch, caplog):
    caplog.set_level(logging.INFO, logger="agent.sender")

    cfg = make_cfg(tmp_path)
    cfg.sender_paths.watch_dir.mkdir()
    cfg.sender_paths.out_dir.mkdir()

    # Create a batch folder
    batch = cfg.sender_paths.watch_dir / "run001"
    batch.mkdir()
    (batch / "a.txt").write_text("hello")

    # Stub subprocess (CLI seal)
    calls = []
    def fake_run(cmd, capture_output, text):
        calls.append(cmd)
        return SimpleNamespace(returncode=0, stdout="ok", stderr="")
    monkeypatch.setattr(sender.subprocess, "run", fake_run)

    sender.run_sender_loop(cfg, once=True)

    # Assert CLI was invoked
    assert calls, "expected sender to invoke CLI seal"
    cmd = calls[0]
    assert "-m" in cmd and "cli.oord_cli" in cmd

    # Assert state file updated
    state_data = json.loads(cfg.sender_paths.state_file.read_text())
    assert state_data["batches"]["run001"]["status"] == "sealed"

    # Assert logs emitted expected events
    msg = " ".join(r.message for r in caplog.records)
    assert "event=seal_start" in msg
    assert "event=seal_success" in msg

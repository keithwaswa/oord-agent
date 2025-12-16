# tests/agent/test_receiver_loop_basic.py
import logging
import json
from pathlib import Path
import zipfile
from types import SimpleNamespace

import agent.receiver as receiver
from agent.config import AgentConfig, CoreConfig, OrgConfig, AgentSection, ReceiverPaths, LoggingConfig

def make_cfg(tmp_path):
    return AgentConfig(
        mode="receiver",
        core=CoreConfig(base_url="http://core"),
        org=OrgConfig(id="ORG"),
        agent=AgentSection(poll_interval_sec=1, settle_seconds=0),
        logging=LoggingConfig(level="INFO"),
        sender_paths=None,
        receiver_paths=ReceiverPaths(
            incoming_dir=tmp_path / "incoming",
            verified_root=tmp_path / "verified",
            quarantine_dir=tmp_path / "quarantine",
            state_file=tmp_path / "state.json",
        ),
    )

def test_receiver_loop_verifies_bundle(tmp_path, monkeypatch, caplog):
    caplog.set_level(logging.INFO, logger="agent.receiver")

    cfg = make_cfg(tmp_path)
    cfg.receiver_paths.incoming_dir.mkdir()
    cfg.receiver_paths.verified_root.mkdir()

    # Create fake bundle.zip with files/foo.txt
    bundle = cfg.receiver_paths.incoming_dir / "oord_bundle_abc123.zip"
    with zipfile.ZipFile(bundle, "w") as z:
        z.writestr("files/foo.txt", "hello")

    # Stub CLI verify
    def fake_run(cmd, capture_output, text):
        return SimpleNamespace(returncode=0, stdout="verified", stderr="")
    monkeypatch.setattr(receiver.subprocess, "run", fake_run)

    receiver.run_receiver_loop(cfg, once=True)

    # Confirm extraction happened
    extracted = cfg.receiver_paths.verified_root / "oord_bundle_abc123" / "foo.txt"
    assert extracted.exists()
    assert extracted.read_text() == "hello"

    # Confirm state updated
    state = json.loads(cfg.receiver_paths.state_file.read_text())
    assert state["processed_bundles"] == {"oord_bundle_abc123.zip": "verified"}

    # Confirm logs
    msg = " ".join(r.message for r in caplog.records)
    assert "event=verify_start" in msg
    assert "event=verify_pass" in msg

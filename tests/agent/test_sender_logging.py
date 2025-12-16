# tests/agent/test_sender_logging.py
import logging
from pathlib import Path
from agent.sender import _log

def test_sender_log_format(caplog):
    caplog.set_level(logging.INFO, logger="agent.sender")

    _log("info", "seal_start", batch_id="B123", out_dir="/x/y")

    assert len(caplog.records) == 1
    rec = caplog.records[0]

    assert "[sender]" in rec.message
    assert "event=seal_start" in rec.message
    assert "batch_id=B123" in rec.message
    assert "out_dir=/x/y" in rec.message
    assert rec.levelname == "INFO"

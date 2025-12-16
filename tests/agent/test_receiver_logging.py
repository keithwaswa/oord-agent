# tests/agent/test_receiver_logging.py
import logging
from agent.receiver import _log

def test_receiver_log_format(caplog):
    caplog.set_level(logging.INFO, logger="agent.receiver")

    _log("info", "verify_pass", bundle="oord_bundle_x.zip")

    assert len(caplog.records) == 1
    rec = caplog.records[0]

    assert "[receiver]" in rec.message
    assert "event=verify_pass" in rec.message
    assert "bundle=oord_bundle_x.zip" in rec.message
    assert rec.levelname == "INFO"

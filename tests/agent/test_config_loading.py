# tests/agent/test_config_loading.py
from pathlib import Path
from agent.config import load_config, LoggingConfig

def test_load_config_with_logging(tmp_path):
    c = tmp_path / "cfg.toml"
    c.write_text("""
    mode = "sender"
    [core]
    base_url = "http://core"
    [org]
    id = "ORG"
    [agent]
    poll_interval_sec = 1
    settle_seconds = 2
    [logging]
    level = "DEBUG"
    file = "%s/log.txt"
    [sender.paths]
    watch_dir = "%s/in"
    out_dir = "%s/out"
    state_file = "%s/state.json"
    """ % (tmp_path, tmp_path, tmp_path, tmp_path))

    cfg = load_config(c)

    assert cfg.logging.level == "DEBUG"
    assert isinstance(cfg.logging.file, Path)
    assert cfg.logging.file.name == "log.txt"

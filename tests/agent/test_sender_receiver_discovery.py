# tests/agent/test_sender_receiver_discovery.py
import os
from pathlib import Path
import zipfile
import json
import time

from agent import receiver, sender
from agent.config import (
    AgentConfig,
    AgentSection,
    CoreConfig,
    OrgConfig,
    ReceiverPaths,
    SenderPaths,
)
from agent.sender import SenderState, SenderBatchStatus
from agent.receiver import ReceiverState, ReceiverBundleStatus


def test_find_ready_batches_respects_state_and_settle(tmp_path: Path) -> None:
    watch_dir = tmp_path / "watch"
    watch_dir.mkdir()

    job1 = watch_dir / "job1"
    job2 = watch_dir / "job2"
    job1.mkdir()
    job2.mkdir()

    # create files with controlled mtimes
    f1 = job1 / "a.txt"
    f2 = job2 / "b.txt"
    f1.write_text("hello", encoding="utf-8")
    f2.write_text("world", encoding="utf-8")

    # set mtimes: job1 older, job2 very recent
    older = 1_000_000.0
    newer = older + 3.0
    os.utime(f1, (older, older))
    os.utime(f2, (newer, newer))

    state = SenderState(
        batches={"job1": SenderBatchStatus(status="sealed")}
    )

    now = older + 10.0  # 10 seconds after older
    settle_seconds = 5

    ready = sender.find_ready_batches(
        watch_dir=watch_dir,
        state=state,
        settle_seconds=settle_seconds,
        now=now,
    )

    # job1 is sealed and must be skipped; job2 is unsealed and stable, so it can be considered ready
    names = {p.name for p in ready}
    assert "job1" not in names

def test_sender_backoff_skips_until_next_retry(tmp_path: Path) -> None:
    watch_dir = tmp_path / "watch"
    watch_dir.mkdir()

    job = watch_dir / "job1"
    job.mkdir()
    (job / "a.txt").write_text("x", encoding="utf-8")

    st = SenderState(
        batches={"job1": SenderBatchStatus(status="retry", attempts=1, next_retry_at_ms=2_000_000)}
    )

    ready = sender.find_ready_batches(watch_dir=watch_dir, state=st, settle_seconds=0, now=1.0)
    assert ready == []


def test_find_ready_bundles_respects_state_and_pattern(tmp_path: Path) -> None:
    incoming = tmp_path / "incoming"
    incoming.mkdir()

    good = incoming / "oord_bundle_good.zip"
    bad = incoming / "random.zip"
    done = incoming / "oord_bundle_done.zip"

    good.write_bytes(b"123")
    bad.write_bytes(b"456")
    done.write_bytes(b"789")

    older = 1_000_000.0
    os.utime(good, (older, older))
    os.utime(done, (older, older))

    state = ReceiverState(
        bundles={"oord_bundle_done.zip": ReceiverBundleStatus(status="verified")}
    )

    now = older + 10.0
    settle_seconds = 5

    ready = receiver.find_ready_bundles(
        incoming_dir=incoming,
        state=state,
        settle_seconds=settle_seconds,
        now=now,
    )

    names = {p.name for p in ready}
    assert "oord_bundle_good.zip" in names
    assert "random.zip" not in names
    assert "oord_bundle_done.zip" not in names


def test_sender_state_roundtrip(tmp_path: Path) -> None:
    state_path = tmp_path / "sender_state.json"
    original = SenderState(
        batches={"job1": SenderBatchStatus(status="sealed"), "job2": SenderBatchStatus(status="retry", attempts=2)}
    )
    sender.save_state(state_path, original)
    loaded = sender.load_state(state_path)
    assert loaded.batches.keys() == original.batches.keys()
    assert loaded.batches["job1"].status == "sealed"


def test_receiver_state_roundtrip(tmp_path: Path) -> None:
    state_path = tmp_path / "receiver_state.json"
    original = ReceiverState(bundles={"bundle1.zip": ReceiverBundleStatus(status="verified")})
    receiver.save_state(state_path, original)
    loaded = receiver.load_state(state_path)
    assert loaded.bundles.keys() == original.bundles.keys()
    assert loaded.bundles["bundle1.zip"].status == "verified"

def test_sender_once_seals_ready_batch_and_updates_state(tmp_path: Path, monkeypatch) -> None:
    watch_dir = tmp_path / "watch"
    out_dir = tmp_path / "out"
    state_file = tmp_path / "sender_state.json"

    watch_dir.mkdir()
    out_dir.mkdir()

    batch = watch_dir / "job1"
    batch.mkdir()
    (batch / "a.txt").write_text("hello", encoding="utf-8")

    cfg = AgentConfig(
        mode="sender",
        core=CoreConfig(base_url="http://example.test"),
        org=OrgConfig(id="DEMO-ORG"),
        agent=AgentSection(poll_interval_sec=1, settle_seconds=0, recursive=True),
        sender_paths=SenderPaths(
            watch_dir=watch_dir,
            out_dir=out_dir,
            state_file=state_file,
        ),
        receiver_paths=None,
    )

    calls: list[Path] = []

    def fake_seal_batch_via_cli(_cfg, batch_dir: Path, _out_dir: Path):
        calls.append(batch_dir)
        return 0, "sealed-ok", ""

    monkeypatch.setattr(sender, "seal_batch_via_cli", fake_seal_batch_via_cli)

    sender.run_sender_loop(cfg, once=True)

    # batch should have been processed exactly once and state updated
    assert calls == [batch]
    loaded = sender.load_state(state_file)
    assert loaded.batches["job1"].status == "sealed"


def test_sender_once_records_retry_state_on_cli_env_error(tmp_path: Path, monkeypatch) -> None:
    watch_dir = tmp_path / "watch"
    out_dir = tmp_path / "out"
    state_file = tmp_path / "sender_state.json"

    watch_dir.mkdir()
    out_dir.mkdir()

    batch = watch_dir / "job1"
    batch.mkdir()
    (batch / "a.txt").write_text("hello", encoding="utf-8")

    cfg = AgentConfig(
        mode="sender",
        core=CoreConfig(base_url="http://example.test"),
        org=OrgConfig(id="DEMO-ORG"),
        agent=AgentSection(poll_interval_sec=1, settle_seconds=0, recursive=True),
        sender_paths=SenderPaths(
            watch_dir=watch_dir,
            out_dir=out_dir,
            state_file=state_file,
        ),
        receiver_paths=None,
    )

    def fake_seal_batch_via_cli(_cfg, _batch_dir: Path, _out_dir: Path):
        # Non-zero exit simulates env/usage error; state should not be updated
        return 2, "", "env-error"

    monkeypatch.setattr(sender, "seal_batch_via_cli", fake_seal_batch_via_cli)

    sender.run_sender_loop(cfg, once=True)

    loaded = sender.load_state(state_file)
    # Env/usage error should NOT mark sealed, but should persist retry metadata
    assert "job1" in loaded.batches
    st = loaded.batches["job1"]
    assert st.status == "retry"
    assert st.attempts == 1
    assert st.last_exit_code == 2
    assert st.last_error == "env-error"
    # next_retry_at_ms is time-based; just assert it exists and is an int
    assert isinstance(st.next_retry_at_ms, int)
    assert st.next_retry_at_ms > 0



def _make_test_bundle_with_file(bundle_path: Path) -> None:
    bundle_path.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(bundle_path, "w") as z:
        z.writestr(
            "manifest.json",
            json.dumps(
                {
                    "manifest_version": "1.0",
                    "org_id": "DEMO-ORG",
                    "batch_id": "BATCH-1",
                    "created_at_ms": 0,
                    "key_id": "stub-kid",
                    "hash_alg": "sha256",
                    "merkle": {"root_cid": "cid:sha256:" + "a" * 64, "tree_alg": "binary_merkle_sha256"},
                    "files": [{"path": "files/a.txt", "sha256": "0" * 64, "size_bytes": 5}],
                    "signature": "stub",
                },
                sort_keys=True,
            ),
        )
        z.writestr("files/a.txt", "hello")


def test_receiver_once_verifies_and_extracts(tmp_path: Path, monkeypatch) -> None:
    incoming_dir = tmp_path / "incoming"
    verified_root = tmp_path / "verified"
    quarantine_dir = tmp_path / "quarantine"
    state_file = tmp_path / "receiver_state.json"

    bundle = incoming_dir / "oord_bundle_demo.zip"
    _make_test_bundle_with_file(bundle)

    cfg = AgentConfig(
        mode="receiver",
        core=CoreConfig(base_url="http://example.test"),
        org=OrgConfig(id="DEMO-ORG"),
        agent=AgentSection(poll_interval_sec=1, settle_seconds=0, recursive=True),
        sender_paths=None,
        receiver_paths=ReceiverPaths(
            incoming_dir=incoming_dir,
            verified_root=verified_root,
            quarantine_dir=quarantine_dir,
            state_file=state_file,
        ),
    )

    def fake_verify_bundle_via_cli(_cfg, _bundle_path: Path):
        return 0, "verify-ok", ""

    monkeypatch.setattr(receiver, "verify_bundle_via_cli", fake_verify_bundle_via_cli)

    receiver.run_receiver_loop(cfg, once=True)

    loaded = receiver.load_state(state_file)
    assert loaded.bundles["oord_bundle_demo.zip"].status == "verified"

    extracted = verified_root / "DEMO-ORG" / "BATCH-1" / "oord_bundle_demo" / "a.txt"
    assert extracted.is_file()
    assert extracted.read_text(encoding="utf-8") == "hello"


def test_receiver_once_quarantines_on_verify_failure(tmp_path: Path, monkeypatch) -> None:
    incoming_dir = tmp_path / "incoming"
    verified_root = tmp_path / "verified"
    quarantine_dir = tmp_path / "quarantine"
    state_file = tmp_path / "receiver_state.json"

    bundle = incoming_dir / "oord_bundle_demo.zip"
    _make_test_bundle_with_file(bundle)

    cfg = AgentConfig(
        mode="receiver",
        core=CoreConfig(base_url="http://example.test"),
        org=OrgConfig(id="DEMO-ORG"),
        agent=AgentSection(poll_interval_sec=1, settle_seconds=0, recursive=True),
        sender_paths=None,
        receiver_paths=ReceiverPaths(
            incoming_dir=incoming_dir,
            verified_root=verified_root,
            quarantine_dir=quarantine_dir,
            state_file=state_file,
        ),
    )

    def fake_verify_bundle_via_cli(_cfg, _bundle_path: Path):
        # Exit code 1 = verification failure → quarantine
        return 1, "", "verify-failed"

    monkeypatch.setattr(receiver, "verify_bundle_via_cli", fake_verify_bundle_via_cli)

    receiver.run_receiver_loop(cfg, once=True)

    loaded = receiver.load_state(state_file)
    assert loaded.bundles["oord_bundle_demo.zip"].status == "quarantined"
    # bundle should have been moved out of incoming and into quarantine
    assert not bundle.exists()
    assert (quarantine_dir / "oord_bundle_demo.zip").is_file()


def test_receiver_once_on_env_error_keeps_bundle_unprocessed(tmp_path: Path, monkeypatch) -> None:
    incoming_dir = tmp_path / "incoming"
    verified_root = tmp_path / "verified"
    quarantine_dir = tmp_path / "quarantine"
    state_file = tmp_path / "receiver_state.json"

    bundle = incoming_dir / "oord_bundle_demo.zip"
    _make_test_bundle_with_file(bundle)

    cfg = AgentConfig(
        mode="receiver",
        core=CoreConfig(base_url="http://example.test"),
        org=OrgConfig(id="DEMO-ORG"),
        agent=AgentSection(poll_interval_sec=1, settle_seconds=0, recursive=True),
        sender_paths=None,
        receiver_paths=ReceiverPaths(
            incoming_dir=incoming_dir,
            verified_root=verified_root,
            quarantine_dir=quarantine_dir,
            state_file=state_file,
        ),
    )

    def fake_verify_bundle_via_cli(_cfg, _bundle_path: Path):
        # Exit code 2+ = env/usage error; bundle must remain unprocessed in-place
        return 2, "", "env-error"

    monkeypatch.setattr(receiver, "verify_bundle_via_cli", fake_verify_bundle_via_cli)

    receiver.run_receiver_loop(cfg, once=True)

    loaded = receiver.load_state(state_file)
    assert loaded.bundles["oord_bundle_demo.zip"].status == "retry"
    # bundle should still be in incoming, not moved or extracted
    assert bundle.is_file()
    assert not verified_root.exists()
    assert not quarantine_dir.exists()


def test_receiver_extract_is_staged(tmp_path: Path) -> None:
    incoming = tmp_path / "incoming"
    verified = tmp_path / "verified"
    incoming.mkdir()
    verified.mkdir()

    bundle = incoming / "oord_bundle_demo.zip"
    _make_test_bundle_with_file(bundle)

    dest = receiver._extract_verified_files(bundle, verified)
    assert dest.exists()
    assert not dest.with_name(dest.name + ".tmp").exists()


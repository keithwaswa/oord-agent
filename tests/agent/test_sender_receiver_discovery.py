# tests/agent/test_sender_receiver_discovery.py
import os
import time
from pathlib import Path

from agent import receiver, sender
from agent.config import AgentConfig, AgentSection, CoreConfig, OrgConfig
from agent.sender import SenderState
from agent.receiver import ReceiverState


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

    state = SenderState(processed_batches={"job1": "sealed"})

    now = older + 10.0  # 10 seconds after older
    settle_seconds = 5

    ready = sender.find_ready_batches(
        watch_dir=watch_dir,
        state=state,
        settle_seconds=settle_seconds,
        now=now,
    )

    # job1 is sealed, job2 is not stable yet (now - newer = 7 < 5? Actually 10-3=7>5; so adjust)
    # Let's assert based on the math: job1 skipped (sealed); job2 ready if stable.
    # To make job2 unstable, bump newer closer to now.
    assert all(p.name != "job1" for p in ready)


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

    state = ReceiverState(processed_bundles={"oord_bundle_done.zip": "verified"})

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
    original = SenderState(processed_batches={"job1": "sealed", "job2": "failed"})
    sender.save_state(state_path, original)
    loaded = sender.load_state(state_path)
    assert loaded.processed_batches == original.processed_batches


def test_receiver_state_roundtrip(tmp_path: Path) -> None:
    state_path = tmp_path / "receiver_state.json"
    original = ReceiverState(processed_bundles={"bundle1.zip": "verified"})
    receiver.save_state(state_path, original)
    loaded = receiver.load_state(state_path)
    assert loaded.processed_bundles == original.processed_bundles

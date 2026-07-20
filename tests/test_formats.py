"""Multi-format sealing: ROS 1 .bag read directly (no conversion).

Skipped unless the optional `rosbags` dependency is installed (`veriseal[ros1]`).
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from veriseal.formats import FORMAT_MCAP, FORMAT_ROSBAG1, detect_format
from veriseal.seal import seal
from veriseal.verify import verify_seal

rosbags = pytest.importorskip("rosbags")


# ── helpers ──────────────────────────────────────────────────────────────────


def _write_bag(path: Path, messages: list[tuple[str, int, str]]) -> Path:
    """Write a tiny ROS 1 .bag with std_msgs/String messages: (topic, t_ns, text)."""
    from rosbags.rosbag1 import Writer
    from rosbags.typesys import Stores, get_typestore

    ts = get_typestore(Stores.ROS1_NOETIC)
    String = ts.types["std_msgs/msg/String"]
    topics = sorted({t for t, _, _ in messages})
    with Writer(path) as writer:
        conns = {
            topic: writer.add_connection(topic, String.__msgtype__, typestore=ts)
            for topic in topics
        }
        for topic, t_ns, text in messages:
            payload = ts.serialize_ros1(String(data=text), String.__msgtype__)
            writer.write(conns[topic], t_ns, payload)
    return path


_BASE = 1_700_000_000_000_000_000
_MESSAGES = [
    ("/pose", _BASE + 0, "p0"),
    ("/status", _BASE + 1, "ok0"),
    ("/pose", _BASE + 2, "p1"),
    ("/status", _BASE + 3, "ok1"),
]


# ── format detection ─────────────────────────────────────────────────────────


def test_detect_format() -> None:
    assert detect_format(Path("log.mcap")) == FORMAT_MCAP
    assert detect_format(Path("log.bag")) == FORMAT_ROSBAG1
    assert detect_format(Path("LOG.BAG")) == FORMAT_ROSBAG1


def test_detect_format_unknown_raises() -> None:
    with pytest.raises(ValueError, match="Unrecognized log format"):
        detect_format(Path("log.txt"))


# ── seal + verify a .bag directly ─────────────────────────────────────────────


def test_seal_bag_records_format(tmp_path: Path) -> None:
    bag = _write_bag(tmp_path / "in.bag", _MESSAGES)
    seal_path = tmp_path / "in.seal.json"
    seal(bag, key_path=None, out_path=seal_path, do_anchor=False)
    manifest = json.loads(seal_path.read_bytes())
    assert manifest["source"]["format"] == "rosbag1"
    assert manifest["source"]["filename"] == "in.bag"
    assert manifest["messages"]["count"] == len(_MESSAGES)


def test_verify_bag_intact(tmp_path: Path) -> None:
    bag = _write_bag(tmp_path / "in.bag", _MESSAGES)
    seal_path = tmp_path / "in.seal.json"
    seal(bag, key_path=None, out_path=seal_path, do_anchor=False)
    assert verify_seal(bag, seal_path) == 0


def test_verify_bag_tampered(tmp_path: Path) -> None:
    """A .bag with one changed message must verify as TAMPERED against the seal."""
    bag = _write_bag(tmp_path / "orig.bag", _MESSAGES)
    seal_path = tmp_path / "orig.seal.json"
    seal(bag, key_path=None, out_path=seal_path, do_anchor=False)

    tampered = [
        ("/pose", _BASE + 0, "p0"),
        ("/status", _BASE + 1, "ok0"),
        ("/pose", _BASE + 2, "CHANGED"),  # payload differs
        ("/status", _BASE + 3, "ok1"),
    ]
    tampered_bag = _write_bag(tmp_path / "tampered.bag", tampered)
    assert verify_seal(tampered_bag, seal_path) == 1


def test_bag_and_mcap_share_pipeline(tmp_path: Path) -> None:
    """Round-trip through the same seal/verify functions the CLI uses."""
    bag = _write_bag(tmp_path / "rt.bag", _MESSAGES)
    seal_path = tmp_path / "rt.seal.json"
    from typer.testing import CliRunner

    from veriseal.cli import app

    runner = CliRunner()
    r_seal = runner.invoke(
        app, ["seal", str(bag), "--no-anchor", "--out", str(seal_path)]
    )
    assert r_seal.exit_code == 0
    r_verify = runner.invoke(app, ["verify", str(bag), str(seal_path)])
    assert r_verify.exit_code == 0

"""Hermetic tests for veriseal verify (no network)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from mcap.writer import Writer

from veriseal.seal import seal
from veriseal.verify import verify_seal

# ── helpers ──────────────────────────────────────────────────────────────────


def _write_mcap(path: Path, messages: list[tuple[str, int, bytes]]) -> Path:
    """Write an MCAP to *path* with the given (topic, log_time_ns, payload) triples."""
    topics = sorted({topic for topic, _, _ in messages})
    with open(path, "wb") as f:
        writer = Writer(f)
        writer.start()
        schema_id = writer.register_schema(name="raw", encoding="", data=b"")
        channel_ids: dict[str, int] = {
            topic: writer.register_channel(
                topic=topic, message_encoding="", schema_id=schema_id
            )
            for topic in topics
        }
        for topic, log_time, data in messages:
            writer.add_message(
                channel_id=channel_ids[topic],
                log_time=log_time,
                data=data,
                publish_time=log_time,
            )
        writer.finish()
    return path


# Canonical 5-message dataset used across all tests.
_MESSAGES: list[tuple[str, int, bytes]] = [
    ("/pose", 1_000_000, b"\x01"),
    ("/status", 2_000_000, b"\xaa"),
    ("/pose", 3_000_000, b"\x02"),
    ("/status", 4_000_000, b"\xbb"),
    ("/pose", 5_000_000, b"\x03"),
]


@pytest.fixture
def sealed_pair(tmp_path: Path) -> tuple[Path, Path]:
    """Return (mcap_path, seal_path) for the canonical 5-message dataset."""
    mcap = _write_mcap(tmp_path / "orig.mcap", _MESSAGES)
    seal_path = tmp_path / "orig.seal.json"
    seal(mcap, key_path=None, out_path=seal_path)
    return mcap, seal_path


# ── INTACT ────────────────────────────────────────────────────────────────────


def test_intact_returns_0(sealed_pair: tuple[Path, Path]) -> None:
    mcap, seal_path = sealed_pair
    assert verify_seal(mcap, seal_path) == 0


def test_intact_message_count(sealed_pair: tuple[Path, Path]) -> None:
    _, seal_path = sealed_pair
    manifest = json.loads(seal_path.read_bytes())
    assert manifest["messages"]["count"] == 5


# ── TAMPERED: payload changed (MODIFIED) ─────────────────────────────────────


def test_modified_payload_returns_1(sealed_pair: tuple[Path, Path], tmp_path: Path) -> None:
    """Changing /pose t=3_000_000 payload from 0x02 to 0xFF must be detected."""
    _, seal_path = sealed_pair
    tampered_msgs = [
        ("/pose", 1_000_000, b"\x01"),
        ("/status", 2_000_000, b"\xaa"),
        ("/pose", 3_000_000, b"\xFF"),  # payload changed
        ("/status", 4_000_000, b"\xbb"),
        ("/pose", 5_000_000, b"\x03"),
    ]
    tampered_mcap = _write_mcap(tmp_path / "tampered.mcap", tampered_msgs)
    assert verify_seal(tampered_mcap, seal_path) == 1


def test_modified_payload_locates_message(
    sealed_pair: tuple[Path, Path], tmp_path: Path
) -> None:
    """The manifest leaf for (/pose, 3_000_000) must differ from the tampered leaf."""
    _, seal_path = sealed_pair
    tampered_msgs = [
        ("/pose", 1_000_000, b"\x01"),
        ("/status", 2_000_000, b"\xaa"),
        ("/pose", 3_000_000, b"\xFF"),  # payload changed
        ("/status", 4_000_000, b"\xbb"),
        ("/pose", 5_000_000, b"\x03"),
    ]
    _write_mcap(tmp_path / "tampered2.mcap", tampered_msgs)
    from veriseal.merkle import leaf_hash

    original_lh = leaf_hash("/pose", 3_000_000, b"\x02").hex()
    tampered_lh = leaf_hash("/pose", 3_000_000, b"\xFF").hex()
    assert original_lh != tampered_lh
    manifest = json.loads(seal_path.read_bytes())
    leaves_by_key = {
        (entry["topic"], entry["log_time"]): entry["leaf_hash"]
        for entry in manifest["leaves"]
    }
    assert leaves_by_key[("/pose", 3_000_000)] == original_lh


# ── TAMPERED: message removed (REMOVED) ──────────────────────────────────────


def test_removed_message_returns_1(sealed_pair: tuple[Path, Path], tmp_path: Path) -> None:
    _, seal_path = sealed_pair
    reduced_msgs = [m for m in _MESSAGES if not (m[0] == "/status" and m[1] == 4_000_000)]
    assert len(reduced_msgs) == 4
    reduced_mcap = _write_mcap(tmp_path / "reduced.mcap", reduced_msgs)
    assert verify_seal(reduced_mcap, seal_path) == 1


def test_removed_message_locates(sealed_pair: tuple[Path, Path], tmp_path: Path) -> None:
    """The (topic, log_time) of the dropped message must be absent from the recomputed set."""
    _, seal_path = sealed_pair
    reduced_msgs = [m for m in _MESSAGES if not (m[0] == "/status" and m[1] == 4_000_000)]
    reduced_mcap = _write_mcap(tmp_path / "reduced2.mcap", reduced_msgs)
    from veriseal.mcap_io import iter_messages
    from veriseal.merkle import leaf_hash as lh_fn

    manifest = json.loads(seal_path.read_bytes())
    manifest_keys = {(entry["topic"], entry["log_time"]) for entry in manifest["leaves"]}
    rec_keys = {(t, lt) for t, lt, _ in iter_messages(reduced_mcap)}
    removed = manifest_keys - rec_keys
    assert ("/status", 4_000_000) in removed
    assert lh_fn  # silence unused import warning


# ── TAMPERED: message added (ADDED) ──────────────────────────────────────────


def test_added_message_returns_1(sealed_pair: tuple[Path, Path], tmp_path: Path) -> None:
    _, seal_path = sealed_pair
    expanded_msgs = _MESSAGES + [("/pose", 6_000_000, b"\x04")]
    expanded_mcap = _write_mcap(tmp_path / "expanded.mcap", expanded_msgs)
    assert verify_seal(expanded_mcap, seal_path) == 1


def test_added_message_locates(sealed_pair: tuple[Path, Path], tmp_path: Path) -> None:
    _, seal_path = sealed_pair
    expanded_msgs = _MESSAGES + [("/pose", 6_000_000, b"\x04")]
    expanded_mcap = _write_mcap(tmp_path / "expanded2.mcap", expanded_msgs)
    from veriseal.mcap_io import iter_messages

    manifest = json.loads(seal_path.read_bytes())
    manifest_keys = {(entry["topic"], entry["log_time"]) for entry in manifest["leaves"]}
    rec_keys = {(t, lt) for t, lt, _ in iter_messages(expanded_mcap)}
    added = rec_keys - manifest_keys
    assert ("/pose", 6_000_000) in added


# ── TAMPERED: manifest field corrupted → signature invalid ───────────────────


def test_corrupted_manifest_field_returns_1(
    sealed_pair: tuple[Path, Path], tmp_path: Path
) -> None:
    """Changing created_utc in the manifest must invalidate the signature."""
    mcap, seal_path = sealed_pair
    manifest = json.loads(seal_path.read_bytes())
    manifest["created_utc"] = "1970-01-01T00:00:00Z"
    corrupt_seal = tmp_path / "corrupt.seal.json"
    from veriseal.canonical import canonical_json

    corrupt_seal.write_bytes(canonical_json(manifest))
    assert verify_seal(mcap, corrupt_seal) == 1


def test_corrupted_merkle_root_returns_1(
    sealed_pair: tuple[Path, Path], tmp_path: Path
) -> None:
    """Zeroing the merkle root in the manifest must fail (root mismatch + sig invalid)."""
    mcap, seal_path = sealed_pair
    manifest = json.loads(seal_path.read_bytes())
    manifest["merkle"]["root"] = "00" * 32
    corrupt_seal = tmp_path / "corrupt_root.seal.json"
    from veriseal.canonical import canonical_json

    corrupt_seal.write_bytes(canonical_json(manifest))
    assert verify_seal(mcap, corrupt_seal) == 1

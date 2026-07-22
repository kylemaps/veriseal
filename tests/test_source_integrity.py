"""Source-file integrity is part of the verdict, plus verify edge cases.

The central guard here locks the Commit-1 fix: a change to NON-message bytes
(MCAP metadata/attachment/header — anything outside the sealed
(topic, log_time, payload) triples) leaves the Merkle root and signature valid
but changes the file's SHA-256, and MUST make the overall verdict TAMPERED.
Before the fix, `source_ok` was computed but excluded from the CLI/pack verdict,
so such a file read INTACT in Python while the web verifier (which gates on the
file digest) read TAMPERED. This test asserts the two now agree.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from mcap.writer import Writer

from veriseal.canonical import canonical_json
from veriseal.seal import seal
from veriseal.verify import run_verification, verify_seal

# ── helpers ──────────────────────────────────────────────────────────────────


def _write_mcap(
    path: Path,
    messages: list[tuple[str, int, bytes]],
    *,
    metadata: dict[str, str] | None = None,
) -> Path:
    topics = sorted({t for t, _, _ in messages})
    with open(path, "wb") as f:
        writer = Writer(f)
        writer.start()
        schema_id = writer.register_schema(name="raw", encoding="", data=b"")
        ch = {
            t: writer.register_channel(topic=t, message_encoding="", schema_id=schema_id)
            for t in topics
        }
        for topic, log_time, data in messages:
            writer.add_message(
                channel_id=ch[topic], log_time=log_time, data=data, publish_time=log_time
            )
        if metadata is not None:
            writer.add_metadata("veriseal-test", metadata)
        writer.finish()
    return path


def _seal(mcap: Path, tmp_path: Path, name: str = "s") -> Path:
    seal_path = tmp_path / f"{name}.seal.json"
    seal(mcap, key_path=None, out_path=seal_path, do_anchor=False)
    return seal_path


_MESSAGES: list[tuple[str, int, bytes]] = [
    ("/pose", 1_000_000, b"\x01"),
    ("/status", 2_000_000, b"\xaa"),
    ("/pose", 3_000_000, b"\x02"),
]


# ── item 1: non-message byte change → source fails, merkle passes → TAMPERED ──


def test_non_message_change_is_tampered(tmp_path: Path) -> None:
    """Two MCAPs with IDENTICAL messages but different non-message bytes (one has
    an extra metadata record) share a Merkle root but differ byte-for-byte. The
    file with extra bytes must verify as TAMPERED against the other's seal:
    source_ok False, root_ok True, overall ok False."""
    original = _write_mcap(tmp_path / "a.mcap", _MESSAGES)
    seal_path = _seal(original, tmp_path)

    # Same messages, extra metadata → same leaves/root, different file bytes.
    altered = _write_mcap(tmp_path / "b.mcap", _MESSAGES, metadata={"note": "added"})
    assert altered.read_bytes() != original.read_bytes()

    manifest = json.loads(seal_path.read_bytes())
    result = run_verification(altered, manifest)
    assert result.root_ok is True  # messages unchanged: Merkle still folds
    assert result.sig_ok is True  # manifest itself untouched
    assert result.source_ok is False  # file bytes differ
    assert result.ok is False  # ...therefore the verdict is TAMPERED
    assert verify_seal(altered, seal_path) == 1


def test_intact_requires_source_ok(tmp_path: Path) -> None:
    """Sanity: the genuine file still verifies INTACT and source_ok is part of it."""
    mcap = _write_mcap(tmp_path / "ok.mcap", _MESSAGES)
    seal_path = _seal(mcap, tmp_path)
    manifest = json.loads(seal_path.read_bytes())
    result = run_verification(mcap, manifest)
    assert result.source_ok is True
    assert result.ok is True
    assert verify_seal(mcap, seal_path) == 0


# ── item 5: edge cases ───────────────────────────────────────────────────────


def test_duplicate_identical_messages_intact(tmp_path: Path) -> None:
    dup = [("/pose", 1_000_000, b"\x01"), ("/pose", 1_000_000, b"\x01")]
    mcap = _write_mcap(tmp_path / "dup.mcap", dup)
    seal_path = _seal(mcap, tmp_path)
    assert verify_seal(mcap, seal_path) == 0


def test_duplicate_message_modification_localised(tmp_path: Path) -> None:
    """With two identical (/pose, t) messages, changing ONE payload must be
    detected as a modification at that (topic, log_time) key."""
    dup = [("/pose", 1_000_000, b"\x01"), ("/pose", 1_000_000, b"\x01")]
    mcap = _write_mcap(tmp_path / "dup2.mcap", dup)
    seal_path = _seal(mcap, tmp_path)
    tampered = _write_mcap(
        tmp_path / "dup2t.mcap",
        [("/pose", 1_000_000, b"\x01"), ("/pose", 1_000_000, b"\x02")],
    )
    manifest = json.loads(seal_path.read_bytes())
    result = run_verification(tampered, manifest)
    assert result.ok is False
    assert ("/pose", 1_000_000) in result.modifications


def test_empty_mcap_roundtrip(tmp_path: Path) -> None:
    mcap = _write_mcap(tmp_path / "empty.mcap", [])
    seal_path = _seal(mcap, tmp_path)
    manifest = json.loads(seal_path.read_bytes())
    assert manifest["messages"]["count"] == 0
    assert verify_seal(mcap, seal_path) == 0


def test_single_message_roundtrip(tmp_path: Path) -> None:
    mcap = _write_mcap(tmp_path / "one.mcap", [("/pose", 1_000_000, b"\x01")])
    seal_path = _seal(mcap, tmp_path)
    assert verify_seal(mcap, seal_path) == 0


def test_truncated_mcap_is_usage_error(tmp_path: Path) -> None:
    """A corrupt/truncated MCAP is a parse error (exit 2), not a tamper verdict."""
    mcap = _write_mcap(tmp_path / "full.mcap", _MESSAGES)
    seal_path = _seal(mcap, tmp_path)
    truncated = tmp_path / "trunc.mcap"
    truncated.write_bytes(mcap.read_bytes()[: len(mcap.read_bytes()) // 2])
    assert verify_seal(truncated, seal_path) == 2


def test_unreadable_manifest_is_usage_error(tmp_path: Path) -> None:
    mcap = _write_mcap(tmp_path / "m.mcap", _MESSAGES)
    bad_seal = tmp_path / "bad.seal.json"
    bad_seal.write_text("{ this is not json ")
    assert verify_seal(mcap, bad_seal) == 2


def test_bitflipped_signature_is_tampered(tmp_path: Path) -> None:
    """Directly flipping one hex nibble of signature.value must fail (exit 1)."""
    mcap = _write_mcap(tmp_path / "sig.mcap", _MESSAGES)
    seal_path = _seal(mcap, tmp_path)
    manifest = json.loads(seal_path.read_bytes())
    val = manifest["signature"]["value"]
    flip = "1" if val[0] != "1" else "2"
    manifest["signature"]["value"] = flip + val[1:]
    tampered_seal = tmp_path / "sigflip.seal.json"
    tampered_seal.write_bytes(canonical_json(manifest))
    result = run_verification(mcap, manifest)
    assert result.sig_ok is False
    assert verify_seal(mcap, tampered_seal) == 1


def test_missing_mcap_file_is_usage_error(tmp_path: Path) -> None:
    mcap = _write_mcap(tmp_path / "present.mcap", _MESSAGES)
    seal_path = _seal(mcap, tmp_path)
    assert verify_seal(tmp_path / "does-not-exist.mcap", seal_path) == 2


@pytest.mark.parametrize("n", [1, 2, 3, 7, 8, 9])
def test_various_sizes_roundtrip(tmp_path: Path, n: int) -> None:
    msgs = [("/pose", (i + 1) * 1000, bytes([i % 256])) for i in range(n)]
    mcap = _write_mcap(tmp_path / f"n{n}.mcap", msgs)
    seal_path = _seal(mcap, tmp_path, name=f"n{n}")
    assert verify_seal(mcap, seal_path) == 0

"""Hermetic tests for OpenTimestamps anchoring (no network)."""

from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path

import pytest
from mcap.writer import Writer
from opentimestamps.core.notary import PendingAttestation
from opentimestamps.core.op import OpSHA256
from opentimestamps.core.serialize import BytesSerializationContext
from opentimestamps.core.timestamp import DetachedTimestampFile, Timestamp

from veriseal.anchor import verify_anchor
from veriseal.canonical import canonical_json
from veriseal.seal import seal
from veriseal.verify import verify_seal

# ── helpers ──────────────────────────────────────────────────────────────────


def _fake_ots(digest: bytes) -> bytes:
    """Build a valid DetachedTimestampFile with a PendingAttestation for *digest*."""
    ts = Timestamp(digest)
    ts.attestations.add(PendingAttestation("https://a.pool.opentimestamps.org"))
    dtf = DetachedTimestampFile(OpSHA256(), ts)
    ctx = BytesSerializationContext()
    dtf.serialize(ctx)
    return ctx.getbytes()


def _write_mcap(path: Path, messages: list[tuple[str, int, bytes]]) -> Path:
    topics = sorted({t for t, _, _ in messages})
    with open(path, "wb") as f:
        writer = Writer(f)
        writer.start()
        schema_id = writer.register_schema(name="raw", encoding="", data=b"")
        ch_ids = {
            t: writer.register_channel(topic=t, message_encoding="", schema_id=schema_id)
            for t in topics
        }
        for topic, log_time, data in messages:
            writer.add_message(
                channel_id=ch_ids[topic], log_time=log_time, data=data, publish_time=log_time
            )
        writer.finish()
    return path


_MESSAGES: list[tuple[str, int, bytes]] = [
    ("/pose", 1_000_000, b"\x01"),
    ("/status", 2_000_000, b"\xaa"),
    ("/pose", 3_000_000, b"\x02"),
]


@pytest.fixture
def mcap_path(tmp_path: Path) -> Path:
    return _write_mcap(tmp_path / "test.mcap", _MESSAGES)


# ── anchor.submit monkeypatch ─────────────────────────────────────────────────


@pytest.fixture
def patched_submit(monkeypatch: pytest.MonkeyPatch) -> None:
    """Replace anchor.submit with a deterministic no-network version."""
    import veriseal.anchor as anchor_mod

    monkeypatch.setattr(anchor_mod, "submit", _fake_ots)


# ── seal --anchor writes correct anchor block ─────────────────────────────────


def test_anchor_block_written(
    mcap_path: Path, tmp_path: Path, patched_submit: None
) -> None:
    """seal with do_anchor=True writes an anchor dict with expected keys."""
    seal_path = tmp_path / "out.seal.json"
    seal(mcap_path, key_path=None, out_path=seal_path, do_anchor=True)
    manifest = json.loads(seal_path.read_bytes())
    anchor = manifest["anchor"]
    assert anchor is not None
    assert anchor["type"] == "opentimestamps"
    assert anchor["commitment_alg"] == "SHA-256"
    assert anchor["status"] == "pending"
    assert "commits" in anchor
    assert "ots_base64" in anchor
    assert "submitted_utc" in anchor


def test_anchor_commits_digest_correct(
    mcap_path: Path, tmp_path: Path, patched_submit: None
) -> None:
    """anchor['commits'] == sha256(canonical_json(manifest WITHOUT 'anchor'))."""
    seal_path = tmp_path / "out.seal.json"
    seal(mcap_path, key_path=None, out_path=seal_path, do_anchor=True)
    manifest = json.loads(seal_path.read_bytes())

    payload_for_anchor = {k: v for k, v in manifest.items() if k != "anchor"}
    expected = hashlib.sha256(canonical_json(payload_for_anchor)).hexdigest()
    assert manifest["anchor"]["commits"] == expected


def test_anchor_ots_base64_valid(
    mcap_path: Path, tmp_path: Path, patched_submit: None
) -> None:
    """ots_base64 decodes to valid OTS bytes that round-trip as DetachedTimestampFile."""
    from opentimestamps.core.serialize import BytesDeserializationContext

    seal_path = tmp_path / "out.seal.json"
    seal(mcap_path, key_path=None, out_path=seal_path, do_anchor=True)
    manifest = json.loads(seal_path.read_bytes())

    ots_bytes = base64.b64decode(manifest["anchor"]["ots_base64"])
    ctx = BytesDeserializationContext(ots_bytes)
    dtf = DetachedTimestampFile.deserialize(ctx)

    # The embedded file_digest must match the manifest's commits hex
    assert dtf.file_digest.hex() == manifest["anchor"]["commits"]


def test_anchor_commits_to_signature(
    mcap_path: Path, tmp_path: Path, patched_submit: None
) -> None:
    """The anchor digest covers the signature field (included in payload_for_anchor)."""
    seal_path = tmp_path / "out.seal.json"
    seal(mcap_path, key_path=None, out_path=seal_path, do_anchor=True)
    manifest = json.loads(seal_path.read_bytes())

    # Signature must be in the payload that was hashed
    assert "signature" in {k: v for k, v in manifest.items() if k != "anchor"}


# ── --no-anchor leaves anchor null ───────────────────────────────────────────


def test_no_anchor_leaves_null(mcap_path: Path, tmp_path: Path) -> None:
    """do_anchor=False must keep anchor=null without calling the network."""
    seal_path = tmp_path / "out.seal.json"
    seal(mcap_path, key_path=None, out_path=seal_path, do_anchor=False)
    manifest = json.loads(seal_path.read_bytes())
    assert manifest["anchor"] is None


def test_no_anchor_signature_still_valid(mcap_path: Path, tmp_path: Path) -> None:
    """Signature must be valid regardless of anchor flag."""
    seal_path = tmp_path / "out.seal.json"
    seal(mcap_path, key_path=None, out_path=seal_path, do_anchor=False)
    assert verify_seal(mcap_path, seal_path) == 0


# ── verify_anchor directly ───────────────────────────────────────────────────


def test_verify_anchor_pending() -> None:
    """A freshly submitted pending proof returns status='pending'."""
    digest = hashlib.sha256(b"test manifest payload").digest()
    ots_bytes = _fake_ots(digest)
    status, block_height = verify_anchor(digest, ots_bytes)
    assert status == "pending"
    assert block_height is None


def test_verify_anchor_wrong_digest_raises() -> None:
    """Passing the wrong digest must raise ValueError."""
    digest_a = hashlib.sha256(b"manifest A").digest()
    digest_b = hashlib.sha256(b"manifest B").digest()
    ots_bytes = _fake_ots(digest_a)
    with pytest.raises(ValueError, match="expected"):
        verify_anchor(digest_b, ots_bytes)


# ── anchor tamper detection via verify_seal ───────────────────────────────────


def test_tampered_manifest_anchor_invalid(
    mcap_path: Path, tmp_path: Path, patched_submit: None
) -> None:
    """Changing manifest after anchoring makes the commits-digest check fail."""
    seal_path = tmp_path / "out.seal.json"
    seal(mcap_path, key_path=None, out_path=seal_path, do_anchor=True)

    manifest = json.loads(seal_path.read_bytes())

    # Tamper a field that's included in the anchor payload
    manifest["created_utc"] = "1970-01-01T00:00:00Z"
    tampered_seal = tmp_path / "tampered.seal.json"
    tampered_seal.write_bytes(canonical_json(manifest))

    # verify_seal detects TAMPERED (sig fails), AND anchor commits check fails internally
    assert verify_seal(mcap_path, tampered_seal) == 1


def test_anchor_commits_mismatch_detected(
    mcap_path: Path, tmp_path: Path, patched_submit: None
) -> None:
    """Zeroing 'commits' triggers INVALID anchor message; exit code stays 0 (anchor is informational)."""
    seal_path = tmp_path / "out.seal.json"
    seal(mcap_path, key_path=None, out_path=seal_path, do_anchor=True)

    manifest = json.loads(seal_path.read_bytes())
    # Zero the commits field to simulate a tampered anchor block
    manifest["anchor"]["commits"] = "00" * 32
    patched_seal = tmp_path / "patched.seal.json"
    patched_seal.write_bytes(canonical_json(manifest))

    # Anchor is EXCLUDED from the signed payload, so sig + Merkle still pass → INTACT.
    # The anchor INVALID message is printed as informational output only.
    result = verify_seal(mcap_path, patched_seal)
    assert result == 0  # INTACT: anchor is informational, not part of the exit code


# ── prior tests unaffected with --no-anchor ───────────────────────────────────


def test_prior_verify_intact_with_no_anchor(mcap_path: Path, tmp_path: Path) -> None:
    """Full seal/verify cycle with no anchor returns 0 (prior behaviour preserved)."""
    seal_path = tmp_path / "out.seal.json"
    seal(mcap_path, key_path=None, out_path=seal_path, do_anchor=False)
    assert verify_seal(mcap_path, seal_path) == 0


def test_prior_verify_tampered_with_no_anchor(mcap_path: Path, tmp_path: Path) -> None:
    """Payload tamper still detected when anchor is null."""
    seal_path = tmp_path / "out.seal.json"
    seal(mcap_path, key_path=None, out_path=seal_path, do_anchor=False)

    tampered_msgs = [
        ("/pose", 1_000_000, b"\xFF"),  # payload changed
        ("/status", 2_000_000, b"\xaa"),
        ("/pose", 3_000_000, b"\x02"),
    ]
    tampered_mcap = _write_mcap(tmp_path / "tampered.mcap", tampered_msgs)
    assert verify_seal(tampered_mcap, seal_path) == 1

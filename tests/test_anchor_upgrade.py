"""Hermetic tests for `veriseal anchor upgrade` (no network — anchor.upgrade mocked)."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest
from mcap.writer import Writer
from opentimestamps.core.notary import BitcoinBlockHeaderAttestation, PendingAttestation
from opentimestamps.core.op import OpSHA256
from opentimestamps.core.serialize import BytesSerializationContext
from opentimestamps.core.timestamp import DetachedTimestampFile, Timestamp

import veriseal.anchor as anchor_mod
from veriseal.anchor import upgrade_manifest
from veriseal.canonical import canonical_json
from veriseal.seal import seal
from veriseal.verify import verify_seal

# ── helpers ──────────────────────────────────────────────────────────────────


def _pending_ots(digest: bytes) -> bytes:
    ts = Timestamp(digest)
    ts.attestations.add(PendingAttestation("https://a.pool.opentimestamps.org"))
    dtf = DetachedTimestampFile(OpSHA256(), ts)
    ctx = BytesSerializationContext()
    dtf.serialize(ctx)
    return ctx.getbytes()


def _confirmed_ots(digest: bytes, height: int) -> bytes:
    ts = Timestamp(digest)
    ts.attestations.add(BitcoinBlockHeaderAttestation(height))
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


@pytest.fixture
def anchored_seal(mcap_path: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Seal with a fake PENDING anchor (no network) and return the seal path."""
    monkeypatch.setattr(anchor_mod, "submit", _pending_ots)
    seal_path = tmp_path / "out.seal.json"
    seal(mcap_path, key_path=None, out_path=seal_path, do_anchor=True)
    return seal_path


def _anchor_digest(manifest: dict) -> bytes:
    payload = {k: v for k, v in manifest.items() if k != "anchor"}
    return hashlib.sha256(canonical_json(payload)).digest()


# ── status: none ─────────────────────────────────────────────────────────────


def test_upgrade_none_when_no_anchor(mcap_path: Path, tmp_path: Path) -> None:
    seal_path = tmp_path / "na.seal.json"
    seal(mcap_path, key_path=None, out_path=seal_path, do_anchor=False)
    manifest = json.loads(seal_path.read_bytes())
    status, height, changed = upgrade_manifest(manifest)
    assert status == "none"
    assert height is None
    assert changed is False


# ── status: pending (no new attestation) ─────────────────────────────────────


def test_upgrade_pending_unchanged(anchored_seal: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    manifest = json.loads(anchored_seal.read_bytes())
    # calendars return the same bytes (still just pending)
    monkeypatch.setattr(anchor_mod, "upgrade", lambda b: b)
    status, height, changed = upgrade_manifest(manifest)
    assert status == "pending"
    assert height is None
    assert changed is False


# ── status: confirmed ────────────────────────────────────────────────────────


def test_upgrade_confirmed_updates_manifest(
    anchored_seal: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    manifest = json.loads(anchored_seal.read_bytes())
    digest = _anchor_digest(manifest)
    monkeypatch.setattr(anchor_mod, "upgrade", lambda b: _confirmed_ots(digest, 812_345))

    status, height, changed = upgrade_manifest(manifest)
    assert status == "confirmed"
    assert height == 812_345
    assert changed is True
    assert manifest["anchor"]["status"] == "confirmed"
    assert manifest["anchor"]["bitcoin_block_height"] == 812_345


def test_upgrade_confirmed_preserves_signature(
    mcap_path: Path, anchored_seal: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Writing back a confirmed anchor must NOT invalidate the manifest signature
    (the anchor block is excluded from the signed payload)."""
    manifest = json.loads(anchored_seal.read_bytes())
    digest = _anchor_digest(manifest)
    monkeypatch.setattr(anchor_mod, "upgrade", lambda b: _confirmed_ots(digest, 812_345))

    upgrade_manifest(manifest)
    anchored_seal.write_bytes(canonical_json(manifest))

    # Still INTACT after the anchor was upgraded to confirmed.
    assert verify_seal(mcap_path, anchored_seal) == 0


def test_upgrade_confirmed_is_idempotent(
    anchored_seal: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    manifest = json.loads(anchored_seal.read_bytes())
    digest = _anchor_digest(manifest)
    monkeypatch.setattr(anchor_mod, "upgrade", lambda b: _confirmed_ots(digest, 812_345))

    upgrade_manifest(manifest)
    # Second run: already confirmed with the same height and proof -> no change.
    status, height, changed = upgrade_manifest(manifest)
    assert status == "confirmed"
    assert height == 812_345
    assert changed is False


# ── status: mismatch (proof commits to a different manifest) ──────────────────


def test_upgrade_mismatch_does_not_touch_manifest(
    anchored_seal: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    manifest = json.loads(anchored_seal.read_bytes())
    before = json.loads(anchored_seal.read_bytes())
    wrong_digest = hashlib.sha256(b"a different manifest entirely").digest()
    monkeypatch.setattr(anchor_mod, "upgrade", lambda b: _confirmed_ots(wrong_digest, 999))

    status, height, changed = upgrade_manifest(manifest)
    assert status == "mismatch"
    assert changed is False
    assert manifest == before  # untouched


# ── CLI plumbing ─────────────────────────────────────────────────────────────


def test_cli_anchor_upgrade_none_exit0(mcap_path: Path, tmp_path: Path) -> None:
    seal_path = tmp_path / "na.seal.json"
    seal(mcap_path, key_path=None, out_path=seal_path, do_anchor=False)
    from typer.testing import CliRunner

    from veriseal.cli import app

    result = CliRunner().invoke(app, ["anchor", "upgrade", str(seal_path)])
    assert result.exit_code == 0
    assert "Nothing to upgrade" in " ".join(result.stdout.split())


def test_cli_anchor_upgrade_confirmed_writes_back(
    anchored_seal: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    manifest = json.loads(anchored_seal.read_bytes())
    digest = _anchor_digest(manifest)
    monkeypatch.setattr(anchor_mod, "upgrade", lambda b: _confirmed_ots(digest, 812_345))
    from typer.testing import CliRunner

    from veriseal.cli import app

    result = CliRunner().invoke(app, ["anchor", "upgrade", str(anchored_seal)])
    assert result.exit_code == 0
    assert "confirmed" in result.stdout.lower()
    written = json.loads(anchored_seal.read_bytes())
    assert written["anchor"]["status"] == "confirmed"
    assert written["anchor"]["bitcoin_block_height"] == 812_345

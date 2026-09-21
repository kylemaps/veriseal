"""Regression tests for the REAL `anchor.upgrade()` against a fake calendar.

`tests/test_anchor_upgrade.py` mocks `anchor.upgrade` wholesale, so it exercises
`upgrade_manifest`'s bookkeeping but never `upgrade()` itself. That gap let a real
bug ship: `upgrade()` asked each calendar for a proof of `dtf.file_digest` and
merged the reply into the ROOT timestamp. Both are wrong.

A calendar does not commit to the file digest. It appends its own nonce and hashes,
then attests to the result — a node DEEPER in the tree:

    root (msg = file_digest)          <- no attestation
      └─ OpAppend(nonce)              (msg = file_digest || nonce)
           └─ OpSHA256()              (msg = SHA256(file_digest || nonce))  <- PendingAttestation

So querying with `file_digest` returns "not found", and merging a reply for the
deep node into the root raises "Can't merge timestamps for different messages
together". Either way the proof stayed pending forever, and both failures were
swallowed by `except Exception: pass`.

These tests build that exact shape and drive the real `upgrade()` with a fake
calendar that answers ONLY for the deep commitment, so the old behaviour cannot
pass. No network.
"""

from __future__ import annotations

import pytest
from opentimestamps.core.notary import BitcoinBlockHeaderAttestation, PendingAttestation
from opentimestamps.core.op import OpAppend, OpSHA256
from opentimestamps.core.serialize import BytesDeserializationContext, BytesSerializationContext
from opentimestamps.core.timestamp import DetachedTimestampFile, Timestamp

import veriseal.anchor as anchor_mod
from veriseal.anchor import verify_anchor

_CALENDAR_URI = "https://alice.btc.calendar.opentimestamps.org"
_NONCE = bytes(range(16))
_HEIGHT = 962_831


class _CommitmentNotFound(Exception):
    """Stands in for the calendar's real 404 (CommitmentNotFoundError)."""


def _pending_proof(file_digest: bytes) -> tuple[bytes, bytes]:
    """Build a realistic pending proof.

    Returns ``(serialized_ots_bytes, deep_commitment)`` where *deep_commitment* is
    the message the calendar actually attested to — NOT the file digest.
    """
    root = Timestamp(file_digest)
    appended = root.ops.add(OpAppend(_NONCE))
    deep = appended.ops.add(OpSHA256())
    deep.attestations.add(PendingAttestation(_CALENDAR_URI))

    dtf = DetachedTimestampFile(OpSHA256(), root)
    ctx = BytesSerializationContext()
    dtf.serialize(ctx)
    return ctx.getbytes(), deep.msg


def _fake_calendar(answers_for: bytes, queried: list[bytes]):
    """A RemoteCalendar stand-in that only knows *answers_for*."""

    class _FakeCalendar:
        def __init__(self, uri: str) -> None:
            self.uri = uri

        def get_timestamp(self, commitment: bytes, timeout: float | None = None) -> Timestamp:
            queried.append(commitment)
            if commitment != answers_for:
                raise _CommitmentNotFound("Not found")
            confirmed = Timestamp(commitment)
            confirmed.attestations.add(BitcoinBlockHeaderAttestation(_HEIGHT))
            return confirmed

    return _FakeCalendar


@pytest.fixture
def file_digest() -> bytes:
    import hashlib

    return hashlib.sha256(b"veriseal manifest payload").digest()


def test_upgrade_queries_the_attestations_own_commitment(
    file_digest: bytes, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The calendar must be asked about the deep node, never the file digest."""
    ots_bytes, deep_commitment = _pending_proof(file_digest)
    assert deep_commitment != file_digest  # the whole point

    queried: list[bytes] = []
    monkeypatch.setattr(anchor_mod, "RemoteCalendar", _fake_calendar(deep_commitment, queried))

    anchor_mod.upgrade(ots_bytes)

    assert deep_commitment in queried, "upgrade() never asked for the attestation's commitment"
    assert file_digest not in queried, (
        "upgrade() asked the calendar for the FILE DIGEST — the calendar never saw it. "
        "This is the bug that kept every anchor pending forever."
    )


def test_upgrade_merges_into_the_right_node_and_confirms(
    file_digest: bytes, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A confirmed reply must merge in so the proof verifies as confirmed."""
    ots_bytes, deep_commitment = _pending_proof(file_digest)
    monkeypatch.setattr(anchor_mod, "RemoteCalendar", _fake_calendar(deep_commitment, []))

    new_ots = anchor_mod.upgrade(ots_bytes)

    assert new_ots != ots_bytes, "upgrade() returned the proof unchanged"
    status, height = verify_anchor(file_digest, new_ots)
    assert status == "confirmed"
    assert height == _HEIGHT


def test_upgraded_proof_still_binds_the_same_file_digest(
    file_digest: bytes, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Upgrading must not change what the proof commits to."""
    ots_bytes, deep_commitment = _pending_proof(file_digest)
    monkeypatch.setattr(anchor_mod, "RemoteCalendar", _fake_calendar(deep_commitment, []))

    new_ots = anchor_mod.upgrade(ots_bytes)

    ctx = BytesDeserializationContext(new_ots)
    dtf = DetachedTimestampFile.deserialize(ctx)
    assert dtf.file_digest == file_digest


def test_unreachable_calendar_leaves_proof_pending(
    file_digest: bytes, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A calendar that answers nothing must leave the proof pending, not corrupt it.

    Documents the deliberate silent-skip in `upgrade()`: a calendar that is down or
    not yet ready is not an error, it just means "try again later".
    """
    ots_bytes, _ = _pending_proof(file_digest)
    # Answers for a commitment that is in no proof -> every query raises.
    monkeypatch.setattr(anchor_mod, "RemoteCalendar", _fake_calendar(b"\xff" * 32, []))

    new_ots = anchor_mod.upgrade(ots_bytes)

    status, height = verify_anchor(file_digest, new_ots)
    assert status == "pending"
    assert height is None

"""OpenTimestamps anchoring — submit/verify/upgrade OTS proofs."""

from __future__ import annotations

from opentimestamps.calendar import RemoteCalendar
from opentimestamps.core.notary import BitcoinBlockHeaderAttestation, PendingAttestation
from opentimestamps.core.op import OpSHA256
from opentimestamps.core.serialize import BytesDeserializationContext, BytesSerializationContext
from opentimestamps.core.timestamp import DetachedTimestampFile, Timestamp

_CALENDARS = [
    "https://a.pool.opentimestamps.org",
    "https://b.pool.opentimestamps.org",
    "https://c.pool.opentimestamps.org",
    "https://ots.btc.catallaxy.com",
]

_TIMEOUT = 5  # seconds per calendar


def submit(digest: bytes) -> bytes:
    """Submit *digest* to OTS public calendars; return serialized DetachedTimestampFile bytes.

    Tries all calendars; raises RuntimeError if none respond.
    """
    ts = Timestamp(digest)
    file_ts = DetachedTimestampFile(OpSHA256(), ts)

    errors: list[str] = []
    for cal_url in _CALENDARS:
        try:
            cal = RemoteCalendar(cal_url)
            cal_stamp = cal.submit(digest, timeout=_TIMEOUT)
            file_ts.timestamp.merge(cal_stamp)
        except Exception as exc:
            errors.append(f"{cal_url}: {exc}")

    if not list(file_ts.timestamp.all_attestations()):
        raise RuntimeError(f"All calendars unreachable: {'; '.join(errors)}")

    ctx = BytesSerializationContext()
    file_ts.serialize(ctx)
    return ctx.getbytes()


def verify_anchor(digest: bytes, ots_bytes: bytes) -> tuple[str, int | None]:
    """Verify *ots_bytes* against *digest*.

    Returns (status, bitcoin_block_height_or_None) where status is:
      "confirmed" — at least one Bitcoin block attestation is present
      "pending"   — only calendar (pending) attestations present

    Raises ValueError if the embedded proof digest does not match *digest*.
    """
    ctx = BytesDeserializationContext(ots_bytes)
    dtf = DetachedTimestampFile.deserialize(ctx)

    if dtf.file_digest != digest:
        raise ValueError(
            f"OTS proof commits to {dtf.file_digest.hex()[:16]}... "
            f"but expected {digest.hex()[:16]}..."
        )

    for _msg, att in dtf.timestamp.all_attestations():
        if isinstance(att, BitcoinBlockHeaderAttestation):
            return "confirmed", att.height

    return "pending", None


def upgrade(ots_bytes: bytes) -> bytes:
    """Ask calendars to upgrade a pending proof; return new serialized bytes."""
    ctx = BytesDeserializationContext(ots_bytes)
    dtf = DetachedTimestampFile.deserialize(ctx)

    for _msg, att in list(dtf.timestamp.all_attestations()):
        if isinstance(att, PendingAttestation):
            try:
                cal = RemoteCalendar(att.uri)
                upgraded = cal.get_timestamp(dtf.file_digest, timeout=_TIMEOUT)
                dtf.timestamp.merge(upgraded)
            except Exception:
                pass  # silently skip unreachable or not-yet-ready calendars

    new_ctx = BytesSerializationContext()
    dtf.serialize(new_ctx)
    return new_ctx.getbytes()

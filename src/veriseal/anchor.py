"""OpenTimestamps anchoring — submit/verify/upgrade OTS proofs."""

from __future__ import annotations

import base64
import hashlib

from opentimestamps.calendar import RemoteCalendar
from opentimestamps.core.notary import BitcoinBlockHeaderAttestation, PendingAttestation
from opentimestamps.core.op import OpSHA256
from opentimestamps.core.serialize import BytesDeserializationContext, BytesSerializationContext
from opentimestamps.core.timestamp import DetachedTimestampFile, Timestamp

from veriseal.canonical import canonical_json

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


def upgrade_manifest(manifest: dict) -> tuple[str, int | None, bool]:
    """Upgrade a manifest's embedded OpenTimestamps proof in place (network).

    Asks the calendars whether the pending proof is now included in a Bitcoin
    block. The anchor block is EXCLUDED from the signed payload, so updating it
    never invalidates the manifest signature.

    Returns ``(status, block_height, changed)``:
      - ``status``: ``"none"`` (no OTS anchor), ``"mismatch"`` (the proof does not
        commit to this manifest — altered file or wrong proof), ``"pending"``
        (acknowledged by a calendar but not yet in a Bitcoin block), or
        ``"confirmed"``.
      - ``block_height``: the Bitcoin block height if confirmed, else ``None``.
      - ``changed``: whether the manifest's anchor block was modified (new proof
        bytes and/or a newly-recorded confirmation) and should be written back.

    On confirmation, sets ``anchor["status"] = "confirmed"`` and
    ``anchor["bitcoin_block_height"]``. Never records a confirmation the proof
    does not actually carry.
    """
    anchor = manifest.get("anchor")
    if not anchor or anchor.get("type") != "opentimestamps" or not anchor.get("ots_base64"):
        return ("none", None, False)

    old_ots = base64.b64decode(anchor["ots_base64"])
    new_ots = upgrade(old_ots)  # returns old bytes unchanged if calendars unreachable

    payload_for_anchor = {k: v for k, v in manifest.items() if k != "anchor"}
    digest = hashlib.sha256(canonical_json(payload_for_anchor)).digest()
    try:
        status, height = verify_anchor(digest, new_ots)
    except ValueError:
        return ("mismatch", None, False)

    changed = new_ots != old_ots
    if status == "confirmed":
        if anchor.get("status") != "confirmed" or anchor.get("bitcoin_block_height") != height:
            changed = True
        anchor["status"] = "confirmed"
        anchor["bitcoin_block_height"] = height
    if changed:
        anchor["ots_base64"] = base64.b64encode(new_ots).decode("ascii")

    return (status, height, changed)

"""OpenTimestamps anchoring: submit/verify/upgrade OTS proofs, and check them against Bitcoin."""

from __future__ import annotations

import base64
import hashlib
import re
import urllib.request
from collections.abc import Callable, Sequence
from dataclasses import dataclass

from opentimestamps.calendar import RemoteCalendar
from opentimestamps.core.notary import BitcoinBlockHeaderAttestation, PendingAttestation
from opentimestamps.core.op import OpSHA256
from opentimestamps.core.serialize import BytesDeserializationContext, BytesSerializationContext
from opentimestamps.core.timestamp import DetachedTimestampFile, Timestamp

from veriseal import __version__
from veriseal.canonical import canonical_json

_CALENDARS = [
    "https://a.pool.opentimestamps.org",
    "https://b.pool.opentimestamps.org",
    "https://c.pool.opentimestamps.org",
    "https://ots.btc.catallaxy.com",
]

_TIMEOUT = 5  # seconds per calendar

# Independent block explorers (Esplora API) that `check_bitcoin` asks for block headers.
# Every one must answer and agree, so neither can vouch for a block on its own.
BLOCK_SOURCES = (
    "https://mempool.space/api",
    "https://blockstream.info/api",
)

_BLOCK_TIMEOUT = 10  # seconds per request
_HEX64 = re.compile(r"[0-9a-f]{64}")
_HEX160 = re.compile(r"[0-9a-f]{160}")


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
    """Check that *ots_bytes* commits to *digest*, and report what the proof claims.

    Returns (status, bitcoin_block_height_or_None) where status is:
      "confirmed": the proof carries a Bitcoin block attestation, as supplied by a
                   calendar. Not checked against Bitcoin: no block header is fetched.
      "pending":   only calendar (pending) attestations present

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


class BlockSourceError(Exception):
    """A block source was unreachable, returned malformed data, or disagreed with another."""


@dataclass
class BitcoinCheck:
    """Outcome of checking a proof's Bitcoin attestations against real block headers.

    ``status`` is one of:
      "verified":  every source returned the same header for the attested block, and
                   the proof computes that header's Merkle root. The manifest existed
                   no later than that block.
      "false":     the sources agree on the block, but the proof does not compute its
                   Merkle root: the attestation is wrong (forged or corrupted).
      "unchecked": no answer either way: the proof has no Bitcoin attestation yet, a
                   source was unreachable, or the sources disagreed.
    """

    status: str
    height: int | None = None
    block_hash: str | None = None
    block_time: int | None = None  # header timestamp, Unix seconds; set by the miner
    sources: tuple[str, ...] = ()
    detail: str | None = None


def block_hash(header: bytes) -> str:
    """The block hash of an 80-byte header, in the usual display order (hex)."""
    return hashlib.sha256(hashlib.sha256(header).digest()).digest()[::-1].hex()


def _http_get_text(url: str) -> str:
    req = urllib.request.Request(url, headers={"User-Agent": f"veriseal/{__version__}"})
    with urllib.request.urlopen(req, timeout=_BLOCK_TIMEOUT) as resp:
        return resp.read(4096).decode("ascii").strip()


def fetch_block_header(
    height: int,
    sources: Sequence[str] = BLOCK_SOURCES,
    get: Callable[[str], str] = _http_get_text,
) -> tuple[bytes, str]:
    """Fetch the header of the block at *height* from every source (network).

    Returns ``(header, block_hash_hex)``. Raises BlockSourceError unless every source
    answers, each header hashes to the block hash that source reported, and all of
    them return the same header.
    """
    if not sources:
        raise BlockSourceError("no block sources configured")
    headers: list[bytes] = []
    for base in sources:
        try:
            reported = get(f"{base}/block-height/{height}")
            # Checked before it goes into a URL: a source must not steer the next request.
            if not _HEX64.fullmatch(reported):
                raise BlockSourceError(f"malformed block hash {reported[:80]!r}")
            header_hex = get(f"{base}/block/{reported}/header")
            if not _HEX160.fullmatch(header_hex):
                raise BlockSourceError(f"malformed block header {header_hex[:80]!r}")
        except Exception as exc:
            raise BlockSourceError(f"{base}: {exc}") from exc
        header = bytes.fromhex(header_hex)
        if block_hash(header) != reported:
            raise BlockSourceError(
                f"{base}: the header for block #{height} does not hash to {reported[:16]}..."
            )
        headers.append(header)
    if any(h != headers[0] for h in headers[1:]):
        raise BlockSourceError(f"the sources disagree about block #{height}")
    return headers[0], block_hash(headers[0])


def check_bitcoin(
    digest: bytes,
    ots_bytes: bytes,
    sources: Sequence[str] = BLOCK_SOURCES,
    get: Callable[[str], str] = _http_get_text,
) -> BitcoinCheck:
    """Check the proof's Bitcoin attestations against real block headers (network).

    Each attestation says "running this proof gives the Merkle root of block N". For
    each one, fetch block N's header from every source and compare that root with
    what the proof computes. Returns the earliest block that checks out; otherwise a
    "false" result if a block contradicts the proof, else "unchecked". Never raises
    for network trouble: the anchor is left unchecked.

    Raises ValueError if the proof does not commit to *digest*, as verify_anchor does.
    """
    dtf = DetachedTimestampFile.deserialize(BytesDeserializationContext(ots_bytes))
    if dtf.file_digest != digest:
        raise ValueError(
            f"OTS proof commits to {dtf.file_digest.hex()[:16]}... "
            f"but expected {digest.hex()[:16]}..."
        )

    attested = sorted(
        {
            (att.height, msg)
            for msg, att in dtf.timestamp.all_attestations()
            if isinstance(att, BitcoinBlockHeaderAttestation)
        }
    )
    if not attested:
        return BitcoinCheck("unchecked", detail="the proof has no Bitcoin attestation yet")

    headers: dict[int, tuple[bytes, str]] = {}
    problems: list[str] = []
    contradiction: BitcoinCheck | None = None
    for height, msg in attested:
        if height not in headers:
            try:
                headers[height] = fetch_block_header(height, sources, get)
            except BlockSourceError as exc:
                problems.append(str(exc))
                continue
        header, hash_hex = headers[height]
        if header[36:68] == msg:  # the header's Merkle root field
            return BitcoinCheck(
                "verified",
                height=height,
                block_hash=hash_hex,
                block_time=int.from_bytes(header[68:72], "little"),
                sources=tuple(sources),
            )
        if contradiction is None:
            contradiction = BitcoinCheck(
                "false",
                height=height,
                block_hash=hash_hex,
                sources=tuple(sources),
                detail=f"block #{height} does not contain this proof",
            )
    if contradiction is not None:
        return contradiction
    return BitcoinCheck("unchecked", detail="; ".join(problems))


def _walk_timestamps(ts):
    """Yield every Timestamp node in *ts*'s tree, root first."""
    yield ts
    for sub in ts.ops.values():
        yield from _walk_timestamps(sub)


def upgrade(ots_bytes: bytes) -> bytes:
    """Ask calendars to upgrade a pending proof; return new serialized bytes."""
    ctx = BytesDeserializationContext(ots_bytes)
    dtf = DetachedTimestampFile.deserialize(ctx)

    # A pending attestation hangs off a node DEEPER in the tree than the file
    # digest (the calendar commits to the digest after the nonce/append ops it
    # added). So we must (a) ask the calendar about that node's own message, and
    # (b) merge the reply into that same node. Querying with dtf.file_digest
    # 404s, and merging into the root raises "Can't merge timestamps for
    # different messages together". Either way the proof stays pending forever.
    for node in list(_walk_timestamps(dtf.timestamp)):
        for att in list(node.attestations):
            if isinstance(att, PendingAttestation):
                try:
                    cal = RemoteCalendar(att.uri)
                    upgraded = cal.get_timestamp(node.msg, timeout=_TIMEOUT)
                    node.merge(upgraded)
                except Exception:
                    pass  # silently skip unreachable or not-yet-ready calendars

    new_ctx = BytesSerializationContext()
    dtf.serialize(new_ctx)
    return new_ctx.getbytes()


def upgrade_manifest(manifest: dict) -> tuple[str, int | None, bool]:
    """Upgrade a manifest's embedded OpenTimestamps proof in place (network).

    Asks the calendars whether the pending proof is now included in a Bitcoin
    block. The anchor block is excluded from the signed payload, so updating it
    never invalidates the manifest signature.

    Returns ``(status, block_height, changed)``:
      - ``status``: ``"none"`` (no OTS anchor), ``"mismatch"`` (the proof does not
        commit to this manifest: altered file or wrong proof), ``"pending"``
        (acknowledged by a calendar but not yet in a Bitcoin block), or
        ``"confirmed"`` (a calendar supplied a Bitcoin attestation; not checked against
        Bitcoin).
      - ``block_height``: the Bitcoin block height if confirmed, else ``None``.
      - ``changed``: whether the manifest's anchor block was modified (new proof
        bytes and/or a newly-recorded confirmation) and should be written back.

    On confirmation, sets ``anchor["status"] = "confirmed"`` and
    ``anchor["bitcoin_block_height"]``. Never records a confirmation the proof does not carry.
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

"""Checkpoints made while a log is being recorded.

Prototype for a v2 format. The v1 seal and verify commands do not use this module.

Each epoch, a fixed span of log time, ends with a signed head: the message count so far, the
Merkle root over those messages, and the hash of the previous head. An epoch with no messages
still gets a head, so a gap in the epoch numbers always means a head was removed. Signing goes
through a callable that is told the epoch, so a per-epoch key can replace the single key without
changing the head format.

The order rule: an epoch holds the messages whose log times fall inside it, and they join the
tree sorted by log time, ties broken by leaf hash. So the tree depends only on which messages
the log holds, and comes out the same whatever order the recorder wrote them in or a reader or a
conversion returns them. A message that reaches the sealer after its epoch has closed joins the
next head, which lists its leaf as late.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import json
import os
from collections.abc import Callable, Iterable
from dataclasses import dataclass, replace
from pathlib import Path
from typing import BinaryIO

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from veriseal.canonical import canonical_json
from veriseal.formats import iter_messages
from veriseal.merkle import IncrementalTree, leaf_hash, merkle_root
from veriseal.signing import generate_key, public_pem, sign, verify

HEAD_SCHEMA = "veriseal-head-v0"
START_SCHEMA = "veriseal-start-v0"
MANIFEST_SCHEMA = "veriseal-manifest-v2-draft"
_HEAD_DOMAIN = b"veriseal-head-v0\x00"
_START_DOMAIN = b"veriseal-start-v0\x00"
_MANIFEST_DOMAIN = b"veriseal-manifest-v2-draft\x00"
_FIRST_PREV = "00" * 32
_SEED_DOMAIN = b"veriseal-epoch-seed-v0\x00"
_KEY_DOMAIN = b"veriseal-epoch-key-v0\x00"
_COMMIT_DOMAIN = b"veriseal-epoch-commit-v0\x00"
# The identity key's algorithm, named in each start record. Only Ed25519 for now; a TPM key
# (P-256) can be added later without changing the record's shape.
START_ALG = "Ed25519"

Message = tuple[str, int, bytes]
Signer = Callable[[int, bytes], bytes]
SignatureCheck = Callable[[int, bytes, bytes], bool]


def key_signer(key: Ed25519PrivateKey) -> Signer:
    """Sign every epoch with one key. This is the baseline a hacked robot can re-sign."""
    return lambda _epoch, message: sign(key, message)


def key_checker(key_pem: str) -> SignatureCheck:
    """Check every epoch against one public key."""
    return lambda _epoch, message, signature: verify(key_pem, message, signature)


def public_key_of(key: Ed25519PrivateKey) -> str:
    return public_pem(key)


def key_id(identity_pem: str) -> str:
    """Names an identity key: the SHA-256 of its public key in raw form."""
    key = serialization.load_pem_public_key(identity_pem.encode("utf-8"))
    raw = key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return hashlib.sha256(raw).hexdigest()


def _hash(domain: bytes, seed: bytes | bytearray) -> bytes:
    """SHA-256 of *domain* then *seed*, fed separately so no new object holds the seed."""
    digest = hashlib.sha256(domain)
    digest.update(seed)
    return digest.digest()


def _next_seed(seed: bytes | bytearray) -> bytes:
    return _hash(_SEED_DOMAIN, seed)


def _epoch_key(seed: bytes | bytearray) -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(_hash(_KEY_DOMAIN, seed))


def key_commitment(public_keys: list[bytes]) -> str:
    """One value that fixes every epoch's public key. It must leave the robot before the task."""
    leaves = [hashlib.sha256(_COMMIT_DOMAIN + key).digest() for key in public_keys]
    return merkle_root(leaves).hex()


class EpochKeys:
    """Throw-away signing keys, one per epoch, each gone once its epoch is signed.

    Each key comes from a seed, and each seed is the hash of the one before, so a seed gives
    every later key and no earlier one. Signing an epoch overwrites its seed. Whoever takes over
    the recorder afterwards holds nothing that can sign the past.

    The seed lives in one bytearray that each erase overwrites in place, and is hashed straight
    from it. Python still leaves short-lived copies it can't wipe (each new seed and private key
    comes out of the hash as an immutable bytes object), so a real recorder needs a small native
    helper for the seed. bench/memory_dump.py measures what is left on a given platform.
    """

    def __init__(self, count: int, seed: bytes | None = None) -> None:
        self._seed = bytearray(os.urandom(32) if seed is None else seed)
        self._epoch = 0
        self.public_keys: list[bytes] = []
        walker = bytearray(self._seed)
        for _ in range(count):
            self.public_keys.append(_epoch_key(walker).public_key().public_bytes_raw())
            walker[:] = _next_seed(walker)
        walker[:] = bytes(len(walker))

    def sign(self, epoch: int, message: bytes) -> bytes:
        """Sign and erase straight away. A recorder that saves heads should use the two steps."""
        signature = self.sign_only(epoch, message)
        self.erase(epoch)
        return signature

    def sign_only(self, epoch: int, message: bytes) -> bytes:
        """Sign with the current epoch's key and keep it until :meth:`erase`."""
        if epoch != self._epoch:
            raise ValueError(f"no key for epoch {epoch}: the current epoch is {self._epoch}")
        if epoch >= len(self.public_keys):
            raise ValueError("this key chain is used up; start a new one")
        return _epoch_key(self._seed).sign(message)

    def erase(self, epoch: int) -> None:
        """Overwrite this epoch's seed with the next one, once its head is safely saved."""
        if epoch != self._epoch:
            raise ValueError(f"epoch {epoch} is not the current epoch {self._epoch}")
        self._seed[:] = _next_seed(self._seed)
        self._epoch += 1


def epoch_checker(public_keys: list[bytes]) -> SignatureCheck:
    """Check each epoch against its own public key."""

    def check(epoch: int, message: bytes, signature: bytes) -> bool:
        if epoch >= len(public_keys):
            return False
        try:
            Ed25519PublicKey.from_public_bytes(public_keys[epoch]).verify(signature, message)
        except InvalidSignature:
            return False
        return True

    return check


def _signed_bytes(head: dict) -> bytes:
    return _HEAD_DOMAIN + canonical_json({k: v for k, v in head.items() if k != "signature"})


def head_hash(head: dict) -> str:
    return hashlib.sha256(canonical_json(head)).hexdigest()


class StreamSealer:
    """Takes messages as they arrive and signs a head as each epoch ends.

    Each head records where its epochs start (by default the first message's log time) and how
    long they are, so the verifier can check every message's time against the epoch that
    sealed it.

    An epoch closes once a message stamped *reorder_ns* or more past its end arrives, which
    allows that much disorder between topics, or once :meth:`tick` is called *grace_ns* past
    its end, which allows for a recorder that writes in bursts. Until then its messages wait as
    leaf hashes, so the sealer never holds the log itself.

    With *persist* and *erase*, each head is saved before its key is erased: sign, persist,
    then erase. A crash between the two then loses nothing, and if *persist* raises, the
    sealer and the key stay as they were so the head can be tried again. *on_leaves* gets each
    closed epoch's leaves in tree order, for the sidecar.
    """

    def __init__(
        self,
        task_id: str,
        epoch_ns: int,
        signer: Signer,
        start: str | None = None,
        *,
        persist: Callable[[dict], None] | None = None,
        erase: Callable[[int], None] | None = None,
        on_leaves: Callable[[list[bytes]], None] | None = None,
        origin_ns: int | None = None,
        reorder_ns: int = 0,
        grace_ns: int = 0,
    ) -> None:
        if epoch_ns <= 0:
            raise ValueError("epoch_ns must be positive")
        if reorder_ns < 0 or grace_ns < 0:
            raise ValueError("reorder_ns and grace_ns can't be negative")
        self._task_id = task_id
        self._epoch_ns = epoch_ns
        self._signer = signer
        self._start = start
        self._persist = persist
        self._erase = erase
        self._on_leaves = on_leaves
        self._reorder_ns = reorder_ns
        self._grace_ns = grace_ns
        self._tree = IncrementalTree()
        self._start_ns = origin_ns
        self._epoch = 0
        self._prev = _FIRST_PREV
        self._waiting: dict[int, list[tuple[int, bytes]]] = {}  # epoch: (log time, leaf)
        self._late: list[tuple[int, bytes]] = []
        self._newest_ns: int | None = None

    @property
    def epoch(self) -> int:
        """The epoch that is open now."""
        return self._epoch

    def _epoch_of(self, log_time_ns: int) -> int:
        assert self._start_ns is not None
        return (log_time_ns - self._start_ns) // self._epoch_ns

    def _close(self, final: bool) -> dict:
        late = sorted(self._late)
        batch = sorted(late + self._waiting.get(self._epoch, []))
        tree = self._tree.copy()
        for _, leaf in batch:
            tree.append(leaf)
        head = {
            "schema": HEAD_SCHEMA,
            "task_id": self._task_id,
            "start": self._start,
            "epoch": self._epoch,
            "origin_ns": self._start_ns,
            "epoch_ns": self._epoch_ns,
            "tree_size": tree.size,
            "root": tree.root().hex(),
            "late": [leaf.hex() for _, leaf in late],
            "prev_head": self._prev,
            "final": final,
        }
        signature = self._signer(self._epoch, _signed_bytes(head))
        head["signature"] = base64.b64encode(signature).decode("ascii")
        if self._persist:
            self._persist(head)
        if self._erase:
            self._erase(self._epoch)
        self._tree = tree
        self._waiting.pop(self._epoch, None)
        self._late = []
        self._prev = head_hash(head)
        self._epoch += 1
        if self._on_leaves:
            self._on_leaves([leaf for _, leaf in batch])
        return head

    def _close_before(self, epoch: int) -> list[dict]:
        heads = []
        while self._epoch < epoch:
            heads.append(self._close(final=False))
        return heads

    def tick(self, now_ns: int) -> list[dict]:
        """Close every epoch that ended at least *grace_ns* before *now_ns*.

        *now_ns* is on the same clock as the log times. A live recorder calls this on a timer,
        so a quiet spell or a stalled recorder can't keep an epoch's key alive. Before the first
        message, unless an origin was given, there is nothing to protect, so it does nothing.
        """
        if self._start_ns is None:
            return []
        return self._close_before(self._epoch_of(now_ns - self._grace_ns))

    def add(self, topic: str, log_time_ns: int, payload: bytes) -> tuple[bytes, list[dict]]:
        """Add one message. Returns its leaf and any heads that its time closed.

        The heads close before the message is taken in, so if saving one fails, the message
        can simply be added again.
        """
        if self._start_ns is None:
            self._start_ns = log_time_ns
        newest = log_time_ns if self._newest_ns is None else max(self._newest_ns, log_time_ns)
        heads = self._close_before(self._epoch_of(newest - self._reorder_ns))
        leaf = leaf_hash(topic, log_time_ns, payload)
        epoch = self._epoch_of(log_time_ns)
        if epoch < self._epoch:
            self._late.append((log_time_ns, leaf))
        else:
            self._waiting.setdefault(epoch, []).append((log_time_ns, leaf))
        self._newest_ns = newest
        return leaf, heads

    def finish(self) -> list[dict]:
        """Close the recording. Returns the heads this closes, the final head last.

        Messages can still be waiting in epochs after the open one, so those close first.
        """
        last = self._epoch
        if self._newest_ns is not None:
            last = max(last, self._epoch_of(self._newest_ns))
        heads = self._close_before(last)
        heads.append(self._close(final=True))
        return heads


def seal_stream(
    messages: Iterable[Message],
    task_id: str,
    epoch_ns: int,
    signer: Signer,
    heads_path: Path,
    leaves_path: Path | None = None,
    start: str | None = None,
    erase: Callable[[int], None] | None = None,
    sync: bool = False,
) -> list[dict]:
    """Replay *messages* through a sealer, writing heads and, if asked, the leaf sidecar.

    Each head is written before its key is erased. Pass ``keys.sign_only`` and ``keys.erase``
    to get that order with throw-away keys. With *sync*, each head also reaches the disk before
    the erase, which a live recorder needs and a benchmark may skip.
    """
    heads: list[dict] = []
    leaves_file: BinaryIO | None = open(leaves_path, "wb") if leaves_path else None
    try:
        with open(heads_path, "wb") as out:

            def persist(head: dict) -> None:
                out.write(canonical_json(head) + b"\n")
                out.flush()
                if sync:
                    os.fsync(out.fileno())
                heads.append(head)

            def write_leaves(leaves: list[bytes]) -> None:
                assert leaves_file is not None
                leaves_file.write(b"".join(leaves))

            sealer = StreamSealer(
                task_id,
                epoch_ns,
                signer,
                start,
                persist=persist,
                erase=erase,
                on_leaves=write_leaves if leaves_file else None,
            )
            for topic, log_time_ns, payload in messages:
                sealer.add(topic, log_time_ns, payload)
            sealer.finish()
    finally:
        if leaves_file:
            leaves_file.close()
    return heads


def read_heads(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_bytes().splitlines() if line]


def read_leaves(path: Path) -> list[bytes]:
    data = path.read_bytes()
    if len(data) % 32:
        raise ValueError(f"{path.name} is not a whole number of 32-byte leaves")
    return [data[i : i + 32] for i in range(0, len(data), 32)]


@dataclass(frozen=True)
class StreamResult:
    ok: bool
    reason: str
    epoch: int | None = None
    message_index: int | None = None
    segment: int | None = None
    interrupted: tuple[int, ...] = ()
    unprotected_messages: int = 0
    seams_ns: tuple[int, ...] = ()
    late_messages: int = 0
    max_late_ns: int = 0


# How far before the start of the epoch that sealed it a late message may be stamped, and how
# far apart two segments may overlap. Covers a recorder that falls behind the sealer for a
# moment. Measure it on the real robot.
MAX_LAG_NS = 100_000_000
SEALED_TOO_LATE = "a message was sealed too long after its time"


def check_heads(
    heads: list[dict],
    task_id: str,
    check_signature: SignatureCheck,
    start: str | None = None,
    require_final: bool = True,
) -> StreamResult:
    """Check the heads alone: numbering, task, links, sizes, signatures and the final head."""
    if not heads:
        return StreamResult(not require_final, "no heads")
    try:
        return _check_heads(heads, task_id, check_signature, start, require_final)
    except _MALFORMED:
        return StreamResult(False, "a head is malformed")


_MALFORMED = (KeyError, TypeError, ValueError, AttributeError, binascii.Error)
_HEX = frozenset("0123456789abcdef")


def _is_leaf_hex(value: object) -> bool:
    return type(value) is str and len(value) == 64 and _HEX.issuperset(value)


def _check_heads(
    heads: list[dict],
    task_id: str,
    check_signature: SignatureCheck,
    start: str | None,
    require_final: bool,
) -> StreamResult:
    prev, size = _FIRST_PREV, 0
    for index, head in enumerate(heads):
        if head.get("schema") != HEAD_SCHEMA:
            return StreamResult(False, "unknown head schema", index)
        if head.get("epoch") != index:
            return StreamResult(False, "a head is missing or out of order", index)
        if head["task_id"] != task_id:
            return StreamResult(False, "head belongs to a different task", index)
        if head["start"] != start:
            return StreamResult(False, "head belongs to a different start record", index)
        if head["prev_head"] != prev:
            return StreamResult(False, "head does not link to the one before", index)
        if type(head["tree_size"]) is not int or type(head["final"]) is not bool:
            return StreamResult(False, "a head is malformed", index)
        if type(head["epoch_ns"]) is not int or head["epoch_ns"] <= 0:
            return StreamResult(False, "a head is malformed", index)
        if head["origin_ns"] is None and head["tree_size"] > 0:
            return StreamResult(False, "a head is malformed", index)
        if head["origin_ns"] is not None and type(head["origin_ns"]) is not int:
            return StreamResult(False, "a head is malformed", index)
        timing = (heads[0]["origin_ns"], heads[0]["epoch_ns"])
        if (head["origin_ns"], head["epoch_ns"]) != timing:
            return StreamResult(False, "heads disagree on when epochs start", index)
        if head["tree_size"] < size:
            return StreamResult(False, "message count went backwards", index)
        late = head["late"]
        if type(late) is not list or not all(_is_leaf_hex(value) for value in late):
            return StreamResult(False, "a head is malformed", index)
        if len(late) > head["tree_size"] - size:
            return StreamResult(False, "a head lists more late messages than it adds", index)
        signature = base64.b64decode(head["signature"], validate=True)
        if not check_signature(index, _signed_bytes(head), signature):
            return StreamResult(False, "bad signature", index)
        if head["final"] and index != len(heads) - 1:
            return StreamResult(False, "heads continue after the final head", index)
        prev, size = head_hash(head), head["tree_size"]
    if require_final and not heads[-1]["final"]:
        return StreamResult(False, "the final head is missing", len(heads) - 1)
    return StreamResult(True, "heads are intact")


def _name_message(
    order: list[tuple[bytes, int]], leaves: list[bytes] | None, head: dict
) -> int | None:
    """Find the changed message, trusting the sidecar only if it matches the signed head.

    *order* holds each recomputed leaf, in tree order, with its position in the log as given.
    Returns that position, or None when the first difference is a message that is missing.
    """
    size = head["tree_size"]
    if leaves is None or len(leaves) < size or merkle_root(leaves[:size]).hex() != head["root"]:
        return None
    for (recomputed, index), recorded in zip(order, leaves[:size], strict=False):
        if recomputed != recorded:
            return index
    return order[size][1] if len(order) > size else None


def check_log(
    messages: Iterable[Message],
    heads: list[dict],
    leaves: list[bytes] | None = None,
    allow_tail: bool = False,
    max_lag_ns: int | None = MAX_LAG_NS,
) -> StreamResult:
    """Rebuild every epoch from the log and compare it with that epoch's head.

    The messages may come in any order. Each belongs to the epoch its log time falls in, unless
    a head lists it as late, and each epoch joins the tree sorted the way the sealer sorts it.

    A late message may be stamped at most *max_lag_ns* before the start of the epoch that
    sealed it. Without this bound, a hacker could add messages after the hack stamped with
    times from before it, and a replay in time order would show them as part of the protected
    past. With *max_lag_ns* set to None the bound is not applied, and ``max_late_ns`` in the
    result says how late the latest message was. That separates a log that matches its heads
    but was sealed late, as after a recorder stall, from one that does not match them.

    With *allow_tail*, messages after the last head are counted instead of rejected. A recording
    cut short by a power loss ends this way, and no head protects those messages.
    """
    origin_ns = heads[0]["origin_ns"] if heads else None
    epoch_ns = heads[0]["epoch_ns"] if heads else 1
    listed: dict[bytes, list[int]] = {}
    for head in heads:
        for value in head["late"]:
            listed.setdefault(bytes.fromhex(value), []).append(head["epoch"])
    if listed and origin_ns is None:
        return StreamResult(False, "a head is malformed")
    epochs: list[list[tuple[int, bytes, int]]] = [[] for _ in heads]
    tail = late = most_late = 0
    for index, (topic, log_time_ns, payload) in enumerate(messages):
        leaf = leaf_hash(topic, log_time_ns, payload)
        if listed.get(leaf):
            epoch = listed[leaf].pop(0)
            begins = origin_ns + epoch * epoch_ns
            if log_time_ns >= begins:
                return StreamResult(False, "a message's time does not fit its epoch", epoch, index)
            if max_lag_ns is not None and log_time_ns < begins - max_lag_ns:
                # Signed, but too long after its time to count as recorded then. A recorder
                # that stalled past the sealer's grace ends here too, so it has its own reason.
                return StreamResult(False, SEALED_TOO_LATE, epoch, index)
            late, most_late = late + 1, max(most_late, begins - log_time_ns)
        else:
            epoch = len(heads) if origin_ns is None else (log_time_ns - origin_ns) // epoch_ns
            if epoch >= len(heads):
                if not allow_tail:
                    last = heads[-1]["epoch"] if heads else None
                    return StreamResult(False, "log has messages after the final head", last)
                tail += 1
                continue
            if epoch < 0:
                return StreamResult(False, "a message's time does not fit its epoch", 0, index)
        epochs[epoch].append((log_time_ns, leaf, index))
    tree = IncrementalTree()
    order: list[tuple[bytes, int]] = []
    for head, members in zip(heads, epochs, strict=True):
        for _, leaf, index in sorted(members):
            tree.append(leaf)
            order.append((leaf, index))
        if tree.size != head["tree_size"] or tree.root().hex() != head["root"]:
            reason = "log does not match head"
            if tree.size < head["tree_size"]:
                reason = "log is missing messages"
            return StreamResult(False, reason, head["epoch"], _name_message(order, leaves, head))
    return StreamResult(
        True,
        "log matches every head",
        unprotected_messages=tail,
        late_messages=late,
        max_late_ns=most_late,
    )


def verify_stream(
    messages: Iterable[Message],
    heads: list[dict],
    task_id: str,
    check_signature: SignatureCheck,
    leaves: list[bytes] | None = None,
) -> StreamResult:
    """Check the heads, then check the log against them."""
    result = check_heads(heads, task_id, check_signature)
    return check_log(messages, heads, leaves) if result.ok else result


def make_start_record(
    task_id: str,
    executor: str,
    public_keys: list[bytes],
    epoch_ns: int,
    block_hash: str,
    identity: Ed25519PrivateKey,
    segment: int = 0,
) -> dict:
    """The record that ties a task to its keys. Its hash goes on-chain before recording starts.

    *block_hash* is the hash of the block that assigned the task. Nobody could know it earlier,
    so it also shows the recording is no older than the assignment. ``alg`` and ``kid`` name the
    identity key's algorithm and the key itself.
    """
    record = {
        "schema": START_SCHEMA,
        "task_id": task_id,
        "executor": executor,
        "segment": segment,
        "epoch_ns": epoch_ns,
        "block_hash": block_hash,
        "key_commitment": key_commitment(public_keys),
        "alg": START_ALG,
        "kid": key_id(public_pem(identity)),
    }
    signature = sign(identity, _START_DOMAIN + canonical_json(record))
    record["signature"] = base64.b64encode(signature).decode("ascii")
    return record


def start_hash(record: dict) -> str:
    return hashlib.sha256(canonical_json(record)).hexdigest()


def begin_segment(
    task_id: str,
    executor: str,
    key_count: int,
    epoch_ns: int,
    block_hash: str,
    identity: Ed25519PrivateKey,
    segment: int = 0,
) -> tuple[EpochKeys, dict]:
    """Make the keys and start record for one stretch of recording.

    After a power loss the recorder calls this again with the next segment number. It starts a
    new key chain, so no secret needs to survive on disk, and the gap stays visible to verifiers.
    """
    keys = EpochKeys(key_count)
    record = make_start_record(
        task_id, executor, keys.public_keys, epoch_ns, block_hash, identity, segment
    )
    return keys, record


@dataclass
class Segment:
    """One stretch of recording: its start record, public keys, heads and messages."""

    start: dict
    public_keys: list[bytes]
    heads: list[dict]
    messages: Iterable[Message]
    leaves: list[bytes] | None = None


def _check_start(
    record: dict,
    index: int,
    task_id: str,
    block_hash: str,
    identity_pem: str,
    public_keys: list[bytes],
    published: str,
) -> str | None:
    """Return what is wrong with a start record, or None."""
    if record.get("schema") != START_SCHEMA:
        return "unknown start record schema"
    if start_hash(record) != published:
        return "start record does not match the chain"
    if record["task_id"] != task_id:
        return "start record belongs to a different task"
    if record["block_hash"] != block_hash:
        return "start record names a different assignment block"
    if record["segment"] != index:
        return "segments are out of order"
    if record["alg"] != START_ALG:
        return "start record names a signature algorithm this verifier does not know"
    if record["kid"] != key_id(identity_pem):
        return "start record names a different identity key"
    if record["key_commitment"] != key_commitment(public_keys):
        return "public keys do not match the start record"
    unsigned = {k: v for k, v in record.items() if k != "signature"}
    signature = base64.b64decode(record["signature"], validate=True)
    if not verify(identity_pem, _START_DOMAIN + canonical_json(unsigned), signature):
        return "bad start record signature"
    return None


def verify_task(
    segments: list[Segment],
    task_id: str,
    block_hash: str,
    identity_pem: str,
    published: list[str],
    not_before_ns: int | None = None,
    published_at_ns: list[int] | None = None,
    max_lag_ns: int | None = MAX_LAG_NS,
) -> StreamResult:
    """Check a whole task against the start records published on-chain, in order.

    Every published record must be accounted for, so a segment can't be dropped. Only the last
    segment must end with a final head. An earlier one that doesn't is reported in
    ``interrupted``, along with how many of its messages no head protects.

    *not_before_ns* is the time of the assignment block. A message stamped earlier can't belong
    to this task, because the start record names a block that didn't exist yet.

    *published_at_ns* gives, for each start record, when a witness or the chain received it,
    on a clock the robot doesn't control. It is for a recorder that waits for that receipt
    before recording. A message stamped earlier than its segment's receipt is rejected. This
    bounds when content can be stamped, not what it says: after a faked power cut a hacker can
    still re-stamp altered content to times after the restart. What it buys is an honest seam:
    the gap in ``seams_ns`` is then at least as long as the time between the cut and the hack.
    Allow for clock drift before passing these times in.

    Segments may not overlap in time, and ``seams_ns`` reports the gap before each restart.
    """
    if len(segments) != len(published) or not segments:
        return StreamResult(False, "the seal and the chain list different start records")
    if published_at_ns is not None and len(published_at_ns) != len(published):
        return StreamResult(False, "a start record has no publication time")
    interrupted: list[int] = []
    seams: list[int] = []
    overlap_ns = MAX_LAG_NS if max_lag_ns is None else max_lag_ns
    unprotected = late = most_late = 0
    ended_ns: int | None = None
    for index, segment in enumerate(segments):
        last = index == len(segments) - 1
        segment = replace(segment, messages=list(segment.messages))
        times = [log_time for _, log_time, _ in segment.messages]
        if not_before_ns is not None and any(t < not_before_ns for t in times):
            return StreamResult(False, "a message is older than the assignment", segment=index)
        if published_at_ns is not None and any(t < published_at_ns[index] for t in times):
            reason = "a message is older than its start record"
            return StreamResult(False, reason, segment=index)
        if times and ended_ns is not None:
            if min(times) < ended_ns - overlap_ns:
                return StreamResult(False, "segments overlap in time", segment=index)
            seams.append(min(times) - ended_ns)
        if times:
            ended_ns = max(times)
        try:
            problem = _check_start(
                segment.start,
                index,
                task_id,
                block_hash,
                identity_pem,
                segment.public_keys,
                published[index],
            )
        except _MALFORMED:
            problem = "the start record is malformed"
        if problem:
            return StreamResult(False, problem, segment=index)
        checker = epoch_checker(segment.public_keys)
        result = check_heads(segment.heads, task_id, checker, published[index], require_final=last)
        if not result.ok:
            return replace(result, segment=index)
        finished = bool(segment.heads) and segment.heads[-1]["final"]
        if finished and not last:
            return StreamResult(False, "recording continued after a final head", segment=index)
        if segment.heads and segment.heads[0]["epoch_ns"] != segment.start["epoch_ns"]:
            return StreamResult(
                False, "heads and start record disagree on the epoch", segment=index
            )
        result = check_log(
            segment.messages,
            segment.heads,
            segment.leaves,
            allow_tail=not last,
            max_lag_ns=max_lag_ns,
        )
        if not result.ok:
            return replace(result, segment=index)
        late += result.late_messages
        most_late = max(most_late, result.max_late_ns)
        if not finished:
            interrupted.append(index)
            unprotected += result.unprotected_messages
    reason = "task checks out"
    if interrupted:
        reason = f"task checks out, with {len(interrupted)} interruption(s)"
    return StreamResult(
        True,
        reason,
        interrupted=tuple(interrupted),
        unprotected_messages=unprotected,
        seams_ns=tuple(seams),
        late_messages=late,
        max_late_ns=most_late,
    )


def task_manifest(
    task_id: str, executor: str, parts: list[dict], identity: Ed25519PrivateKey
) -> dict:
    """The final signed summary of a task. Each part describes one segment."""
    manifest = {
        "schema_version": MANIFEST_SCHEMA,
        "task_id": task_id,
        "executor": executor,
        "segments": parts,
    }
    signature = sign(identity, _MANIFEST_DOMAIN + canonical_json(manifest))
    manifest["signature"] = base64.b64encode(signature).decode("ascii")
    return manifest


def segment_part(segment: Segment, log_sha256: str, log_size: int) -> dict:
    """Describe a segment for the manifest, tying its heads and its file to the signature."""
    heads = b"".join(canonical_json(head) + b"\n" for head in segment.heads)
    return {
        "start": segment.start,
        "public_keys": [key.hex() for key in segment.public_keys],
        "heads_sha256": hashlib.sha256(heads).hexdigest(),
        "log": {"sha256": log_sha256, "size": log_size},
    }


def proof_hash(manifest: dict) -> str:
    """The value for the contract's proof_hash field. It covers the signature too."""
    return hashlib.sha256(canonical_json(manifest)).hexdigest()


def check_manifest(manifest: dict, identity_pem: str, on_chain: str) -> StreamResult:
    """Check the manifest against its signature and the proof_hash on-chain."""
    if manifest.get("schema_version") != MANIFEST_SCHEMA:
        return StreamResult(False, "unknown manifest schema")
    if proof_hash(manifest) != on_chain:
        return StreamResult(False, "manifest does not match proof_hash on the chain")
    unsigned = {k: v for k, v in manifest.items() if k != "signature"}
    try:
        signature = base64.b64decode(manifest["signature"], validate=True)
    except _MALFORMED:
        return StreamResult(False, "the manifest is malformed")
    if not verify(identity_pem, _MANIFEST_DOMAIN + canonical_json(unsigned), signature):
        return StreamResult(False, "bad manifest signature")
    return StreamResult(True, "manifest is intact")


def _main() -> None:
    """Seal one finished log as if it were being recorded. bench/measure.py runs this."""
    parser = argparse.ArgumentParser(description=_main.__doc__)
    parser.add_argument("log", type=Path)
    parser.add_argument("--epoch-seconds", type=float, required=True)
    parser.add_argument("--keys", type=int, required=True, help="keys to prepare, one per epoch")
    parser.add_argument("--out-dir", type=Path, required=True)
    args = parser.parse_args()
    epoch_ns = int(args.epoch_seconds * 1_000_000_000)
    identity = generate_key()
    keys, record = begin_segment("measure", "measure", args.keys, epoch_ns, "00" * 32, identity)
    seal_stream(
        iter_messages(args.log),
        "measure",
        epoch_ns,
        keys.sign_only,
        args.out_dir / "heads.jsonl",
        args.out_dir / "leaves.bin",
        start_hash(record),
        erase=keys.erase,
    )


if __name__ == "__main__":
    _main()

"""Checkpoints closed on a timer, damaged input rejected cleanly, and timed restarts."""

from __future__ import annotations

import copy

import pytest

from veriseal.signing import generate_key
from veriseal.stream import (
    EpochKeys,
    Segment,
    StreamSealer,
    begin_segment,
    check_heads,
    check_log,
    check_manifest,
    epoch_checker,
    proof_hash,
    public_key_of,
    read_heads,
    seal_stream,
    segment_part,
    start_hash,
    task_manifest,
    verify_task,
)

SECOND = 1_000_000_000
TASK = "task-42"
ROBOT = "0xrobot"
BLOCK = "ab" * 32
KEYS = 20


def _log(count: int = 30, start_ns: int = 0) -> list[tuple[str, int, bytes]]:
    return [(f"/t{i % 3}", start_ns + i * SECOND // 10, i.to_bytes(4, "big")) for i in range(count)]


def _segment(identity, messages, index=0) -> Segment:
    keys, record = begin_segment(TASK, ROBOT, KEYS, SECOND, BLOCK, identity, index)
    sealer = StreamSealer(TASK, SECOND, keys.sign, start_hash(record))
    heads = []
    for message in messages:
        heads += sealer.add(*message)[1]
    heads += sealer.finish()
    return Segment(record, keys.public_keys, heads, messages)


def _interrupted(identity, messages, index=0) -> Segment:
    keys, record = begin_segment(TASK, ROBOT, KEYS, SECOND, BLOCK, identity, index)
    sealer = StreamSealer(TASK, SECOND, keys.sign, start_hash(record))
    heads = []
    for message in messages:
        heads += sealer.add(*message)[1]
    return Segment(record, keys.public_keys, heads, messages)


@pytest.fixture
def identity():
    return generate_key()


def _verify(segments, identity, **kwargs):
    published = [start_hash(segment.start) for segment in segments]
    return verify_task(segments, TASK, BLOCK, public_key_of(identity), published, **kwargs)


# The timer.


def test_tick_closes_epochs_while_the_robot_is_quiet():
    keys = EpochKeys(KEYS)
    public_keys = keys.public_keys
    sealer = StreamSealer(TASK, SECOND, keys.sign)
    sealer.add("/t", 0, b"a")
    heads = sealer.tick(3 * SECOND)
    assert [head["epoch"] for head in heads] == [0, 1, 2]
    assert sealer.tick(3 * SECOND + 1) == []
    heads += sealer.add("/t", 3 * SECOND + 5, b"b")[1]
    heads += sealer.finish()
    messages = [("/t", 0, b"a"), ("/t", 3 * SECOND + 5, b"b")]
    assert check_heads(heads, TASK, epoch_checker(public_keys)).ok
    assert check_log(messages, heads).ok


def test_tick_erases_the_key_for_a_closed_epoch():
    """Without the timer, a quiet robot would keep this key until its next message."""
    keys = EpochKeys(KEYS)
    sealer = StreamSealer(TASK, SECOND, keys.sign)
    sealer.add("/t", 0, b"a")
    sealer.tick(2 * SECOND)
    hacker = copy.deepcopy(keys)
    with pytest.raises(ValueError):
        hacker.sign(0, b"rewrite")


def test_tick_before_any_message_does_nothing():
    sealer = StreamSealer(TASK, SECOND, EpochKeys(KEYS).sign)
    assert sealer.tick(10 * SECOND) == []


# Damaged input gets a clear rejection, not a crash.


@pytest.mark.parametrize(
    "damage",
    [
        lambda head: head.pop("tree_size"),
        lambda head: head.update(tree_size="5"),
        lambda head: head.update(final="no"),
        lambda head: head.update(signature="not base64!"),
        lambda head: head.update(signature=None),
        lambda head: head.pop("prev_head"),
    ],
)
def test_a_damaged_head_is_rejected(identity, damage):
    segment = _segment(identity, _log())
    damage(segment.heads[1])
    result = check_heads(
        segment.heads, TASK, epoch_checker(segment.public_keys), segment.heads[0]["start"]
    )
    assert not result.ok
    assert not _verify([segment], identity).ok


def test_a_head_that_is_not_a_dict_is_rejected(identity):
    segment = _segment(identity, _log())
    segment.heads[1] = ["not", "a", "head"]
    assert _verify([segment], identity).reason == "a head is malformed"


@pytest.mark.parametrize(
    "damage",
    [
        lambda record: record.pop("task_id"),
        lambda record: record.update(signature="***"),
        lambda record: record.pop("key_commitment"),
    ],
)
def test_a_damaged_start_record_is_rejected(identity, damage):
    segment = _segment(identity, _log())
    published = [start_hash(segment.start)]
    damage(segment.start)
    result = verify_task([segment], TASK, BLOCK, public_key_of(identity), published)
    assert not result.ok


def test_a_damaged_manifest_signature_is_rejected(identity):
    segment = _segment(identity, _log())
    manifest = task_manifest(TASK, ROBOT, [segment_part(segment, "aa" * 32, 1)], identity)
    manifest["signature"] = "***"
    result = check_manifest(manifest, public_key_of(identity), proof_hash(manifest))
    assert (result.ok, result.reason) == (False, "the manifest is malformed")


# Timed restarts: a start record only counts from when a witness or the chain received it.


def test_honest_task_passes_with_publication_times(identity):
    segment = _segment(identity, _log(start_ns=5 * SECOND))
    assert _verify([segment], identity, published_at_ns=[5 * SECOND]).ok


def test_honest_restart_after_its_receipt_passes(identity):
    messages = _log(start_ns=5 * SECOND)
    before = _interrupted(identity, messages[:12])
    after = _segment(identity, messages[15:], index=1)
    resumed_at = messages[15][1]
    result = _verify([before, after], identity, published_at_ns=[5 * SECOND, resumed_at])
    assert (result.ok, result.interrupted) == (True, (0,))


def test_faked_power_cut_cannot_refill_the_past(identity):
    """The hacker publishes the restart at the hack, so made-up earlier messages are rejected."""
    messages = _log(start_ns=5 * SECOND)
    before = _interrupted(identity, messages[:12])
    forged = [(topic, time_ns, b"forged") for topic, time_ns, _ in messages[12:]]
    after = _segment(identity, forged, index=1)
    hacked_at = messages[25][1]
    result = _verify([before, after], identity, published_at_ns=[5 * SECOND, hacked_at])
    assert (result.ok, result.reason, result.segment) == (
        False,
        "a message is older than its start record",
        1,
    )


def test_faked_power_cut_can_still_cut_the_past_short(identity):
    """What the hacker keeps: a visible hole, with only post-hack messages after it."""
    messages = _log(start_ns=5 * SECOND)
    before = _interrupted(identity, messages[:12])
    after = _segment(identity, messages[25:], index=1)
    hacked_at = messages[25][1]
    result = _verify([before, after], identity, published_at_ns=[5 * SECOND, hacked_at])
    assert (result.ok, result.interrupted) == (True, (0,))


def test_every_start_record_needs_a_publication_time(identity):
    segment = _segment(identity, _log())
    result = _verify([segment], identity, published_at_ns=[])
    assert (result.ok, result.reason) == (False, "a start record has no publication time")


# Message times must fit the epoch that sealed them.


def test_a_message_backdated_into_a_sealed_epoch_is_rejected(identity):
    """The hacker appends, after the hack, a message stamped inside an early epoch."""
    messages = _log(start_ns=5 * SECOND)
    keys, record = begin_segment(TASK, ROBOT, KEYS, SECOND, BLOCK, identity)
    sealer = StreamSealer(TASK, SECOND, keys.sign, start_hash(record))
    heads = []
    for message in messages[:25]:
        heads += sealer.add(*message)[1]
    forged = ("/t0", messages[3][1], b"fake bin success")
    heads += sealer.add(*forged)[1]
    heads += sealer.finish()
    segment = Segment(record, keys.public_keys, heads, messages[:25] + [forged])
    result = _verify([segment], identity)
    assert (result.ok, result.reason, result.message_index) == (
        False,
        "a message was sealed too long after its time",
        25,
    )


def test_small_disorder_within_the_allowance_passes(identity):
    messages = _log(start_ns=5 * SECOND)
    t = messages[10][1]
    messages[10] = (messages[10][0], t + 50_000_000, messages[10][2])
    messages[11] = (messages[11][0], t + 40_000_000, messages[11][2])
    assert _verify([_segment(identity, messages)], identity).ok


def test_disorder_beyond_the_allowance_is_rejected(identity):
    messages = _log(start_ns=5 * SECOND)
    t = messages[10][1]
    messages[11] = (messages[11][0], t - 250_000_000, messages[11][2])
    result = _verify([_segment(identity, messages)], identity)
    assert (result.ok, result.reason) == (False, "a message was sealed too long after its time")


def test_heads_must_agree_on_when_epochs_start(identity):
    segment = _segment(identity, _log())
    segment.heads[1]["origin_ns"] += 1
    assert not _verify([segment], identity).ok


def test_segments_cannot_overlap_in_time(identity):
    messages = _log(start_ns=5 * SECOND)
    before = _interrupted(identity, messages[:20])
    after = _segment(identity, messages[10:], index=1)
    result = _verify([before, after], identity)
    assert (result.ok, result.reason, result.segment) == (False, "segments overlap in time", 1)


def test_the_gap_before_a_restart_is_reported(identity):
    messages = _log(start_ns=5 * SECOND)
    before = _interrupted(identity, messages[:12])
    after = _segment(identity, messages[20:], index=1)
    result = _verify([before, after], identity)
    assert result.ok
    assert result.seams_ns == (messages[20][1] - messages[11][1],)


# Each head is saved before its key is erased.


def test_each_head_is_saved_before_its_key_is_erased():
    keys = EpochKeys(KEYS)
    seen = []

    def persist(head):
        seen.append((head["epoch"], keys._epoch))

    sealer = StreamSealer(TASK, SECOND, keys.sign_only, persist=persist, erase=keys.erase)
    for message in _log():
        sealer.add(*message)
    sealer.finish()
    assert seen and all(epoch == key_epoch for epoch, key_epoch in seen)
    assert keys._epoch == seen[-1][0] + 1


def test_a_failed_save_keeps_the_key_so_the_head_can_be_retried():
    keys = EpochKeys(KEYS)
    public_keys = keys.public_keys
    attempts = []

    def persist(head):
        attempts.append(head)
        if len(attempts) == 1:
            raise OSError("disk full")

    sealer = StreamSealer(TASK, SECOND, keys.sign_only, persist=persist, erase=keys.erase)
    sealer.add("/t", 0, b"a")
    with pytest.raises(OSError):
        sealer.tick(SECOND)
    assert keys._epoch == 0
    (retried,) = sealer.tick(SECOND)
    heads = [retried, *sealer.finish()]
    assert check_heads(heads, TASK, epoch_checker(public_keys)).ok


def test_seal_stream_with_sync_writes_every_head(tmp_path):
    keys = EpochKeys(KEYS)
    public_keys = keys.public_keys
    path = tmp_path / "heads"
    heads = seal_stream(_log(), TASK, SECOND, keys.sign_only, path, erase=keys.erase, sync=True)
    assert read_heads(path) == heads
    assert check_heads(heads, TASK, epoch_checker(public_keys)).ok

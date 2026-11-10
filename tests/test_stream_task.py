"""A whole task: start records on the chain, power loss, and the final signed proof."""

from __future__ import annotations

import copy
from pathlib import Path

import pytest

from veriseal.signing import generate_key
from veriseal.stream import (
    Segment,
    StreamSealer,
    begin_segment,
    check_manifest,
    proof_hash,
    public_key_of,
    read_leaves,
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
KEYS = 14


def _log(count: int = 100, start_ns: int = 0) -> list[tuple[str, int, bytes]]:
    return [(f"/t{i % 3}", start_ns + i * 100_000_000, i.to_bytes(4, "big")) for i in range(count)]


def _one_segment(tmp_path: Path, identity, messages, task=TASK, block=BLOCK, index=0) -> Segment:
    keys, record = begin_segment(task, ROBOT, KEYS, SECOND, block, identity, index)
    public_keys = keys.public_keys
    heads_path = tmp_path / f"heads-{index}"
    heads = seal_stream(
        messages, task, SECOND, keys.sign, heads_path, tmp_path / f"l{index}", start_hash(record)
    )
    return Segment(record, public_keys, heads, messages, read_leaves(tmp_path / f"l{index}"))


def _interrupted_segment(identity, messages, cut_at: int, index=0) -> Segment:
    """Record until the power goes at message *cut_at*, so no final head is ever written."""
    keys, record = begin_segment(TASK, ROBOT, KEYS, SECOND, BLOCK, identity, index)
    public_keys = keys.public_keys
    sealer = StreamSealer(TASK, SECOND, keys.sign, start_hash(record))
    heads = []
    for topic, log_time, payload in messages[:cut_at]:
        heads += sealer.add(topic, log_time, payload)[1]
    return Segment(record, public_keys, heads, messages[:cut_at])


@pytest.fixture
def identity():
    return generate_key()


def _verify(segments, identity, published=None, block=BLOCK, task=TASK):
    published = published if published is not None else [start_hash(s.start) for s in segments]
    return verify_task(segments, task, block, public_key_of(identity), published)


def test_honest_task_passes(tmp_path: Path, identity):
    result = _verify([_one_segment(tmp_path, identity, _log())], identity)
    assert result.ok
    assert result.interrupted == ()


def test_start_record_must_match_the_chain(tmp_path: Path, identity):
    segment = _one_segment(tmp_path, identity, _log())
    result = _verify([segment], identity, ["00" * 32])
    assert (result.ok, result.reason) == (False, "start record does not match the chain")


def test_old_proof_cannot_be_reused_for_a_new_task(tmp_path: Path, identity):
    old = _one_segment(tmp_path, identity, _log(), task="task-41")
    result = _verify([old], identity)
    assert (result.ok, result.reason) == (False, "start record belongs to a different task")


def test_old_proof_cannot_be_reused_for_a_new_assignment(tmp_path: Path, identity):
    old = _one_segment(tmp_path, identity, _log(), block="cd" * 32)
    result = _verify([old], identity)
    assert (result.ok, result.reason) == (False, "start record names a different assignment block")


def test_a_forged_key_chain_fails_against_the_published_start(tmp_path: Path, identity):
    honest = _one_segment(tmp_path, identity, _log())
    published = [start_hash(honest.start)]
    fake = [(topic, time_ns, b"fabricated") for topic, time_ns, _ in _log()]
    forged = _one_segment(tmp_path, identity, fake)
    result = _verify([forged], identity, published)
    assert (result.ok, result.reason) == (False, "start record does not match the chain")


def test_public_keys_must_match_the_start_record(tmp_path: Path, identity):
    segment = _one_segment(tmp_path, identity, _log())
    segment.public_keys = segment.public_keys[:-1]
    result = _verify([segment], identity)
    assert (result.ok, result.reason) == (False, "public keys do not match the start record")


def test_start_record_needs_the_robots_identity(tmp_path: Path, identity):
    segment = _one_segment(tmp_path, generate_key(), _log())
    result = _verify([segment], identity)
    assert (result.ok, result.reason) == (False, "start record names a different identity key")


def test_a_start_record_changed_after_signing_fails_its_signature(tmp_path: Path, identity):
    segment = _one_segment(tmp_path, identity, _log())
    segment.start["executor"] = "0xsomeone-else"
    result = _verify([segment], identity)
    assert (result.ok, result.reason) == (False, "bad start record signature")


def test_a_start_record_with_an_unknown_algorithm_is_refused(tmp_path: Path, identity):
    segment = _one_segment(tmp_path, identity, _log())
    segment.start["alg"] = "ES256"
    result = _verify([segment], identity)
    reason = "start record names a signature algorithm this verifier does not know"
    assert (result.ok, result.reason) == (False, reason)


def test_heads_cannot_move_between_segments(tmp_path: Path, identity):
    first = _one_segment(tmp_path, identity, _log())
    other = _one_segment(tmp_path, identity, _log())
    first.heads = other.heads
    assert not _verify([first], identity).ok


def test_power_cut_restart_passes_and_shows_the_gap(tmp_path: Path, identity):
    messages = _log()
    before = _interrupted_segment(identity, messages, 55)
    after = _one_segment(tmp_path, identity, messages[55:], index=1)
    result = _verify([before, after], identity)
    assert result.ok
    assert result.interrupted == (0,)
    assert result.unprotected_messages == 5


def test_power_cut_before_the_first_head_is_reported(tmp_path: Path, identity):
    messages = _log()
    before = _interrupted_segment(identity, messages, 5)
    after = _one_segment(tmp_path, identity, messages[5:], index=1)
    result = _verify([before, after], identity)
    assert (result.ok, result.interrupted, result.unprotected_messages) == (True, (0,), 5)


def test_a_change_before_the_power_cut_is_caught(tmp_path: Path, identity):
    messages = _log()
    before = _interrupted_segment(identity, messages, 55)
    changed = list(before.messages)
    changed[25] = (changed[25][0], changed[25][1], b"forged")
    before.messages = changed
    after = _one_segment(tmp_path, identity, messages[55:], index=1)
    result = _verify([before, after], identity)
    assert (result.ok, result.segment, result.epoch) == (False, 0, 2)


def test_a_segment_cannot_be_dropped(tmp_path: Path, identity):
    messages = _log()
    before = _interrupted_segment(identity, messages, 55)
    after = _one_segment(tmp_path, identity, messages[55:], index=1)
    published = [start_hash(before.start), start_hash(after.start)]
    result = _verify([after], identity, published)
    assert (result.ok, result.reason) == (
        False,
        "the seal and the chain list different start records",
    )


def test_segments_cannot_be_reordered(tmp_path: Path, identity):
    messages = _log()
    before = _interrupted_segment(identity, messages, 55)
    after = _one_segment(tmp_path, identity, messages[55:], index=1)
    result = _verify([after, before], identity)
    assert (result.ok, result.reason) == (False, "segments are out of order")


def test_the_last_segment_must_finish(identity):
    result = _verify([_interrupted_segment(identity, _log(), 55)], identity)
    assert (result.ok, result.reason) == (False, "the final head is missing")


def test_a_finished_segment_cannot_be_continued(tmp_path: Path, identity):
    messages = _log()
    first = _one_segment(tmp_path, identity, messages[:50])
    second = _one_segment(tmp_path, identity, messages[50:], index=1)
    result = _verify([first, second], identity)
    assert (result.ok, result.reason) == (False, "recording continued after a final head")


def test_faked_power_cut_keeps_the_past_but_shows_the_gap(tmp_path: Path, identity):
    """A hacked robot can fake an outage. It gains a cut, and the cut stays on the record."""
    messages = _log()
    before = _interrupted_segment(identity, messages, 51)
    fake = [(topic, time_ns, b"fabricated") for topic, time_ns, _ in messages[51:]]
    after = _one_segment(tmp_path, identity, fake, index=1)
    result = _verify([before, after], identity)
    assert result.ok
    assert result.interrupted == (0,)


def test_a_message_older_than_the_assignment_fails(tmp_path: Path, identity):
    messages = _log(start_ns=100 * SECOND)
    segment = _one_segment(tmp_path, identity, messages)
    published = [start_hash(segment.start)]
    args = ([segment], TASK, BLOCK, public_key_of(identity), published)
    assert verify_task(*args, not_before_ns=100 * SECOND).ok
    result = verify_task(*args, not_before_ns=100 * SECOND + 1)
    assert (result.ok, result.reason) == (False, "a message is older than the assignment")


def test_the_assignment_check_reads_a_one_shot_log_once(tmp_path: Path, identity):
    messages = _log()
    segment = _one_segment(tmp_path, identity, messages)
    segment.messages = iter(messages)
    result = verify_task(
        [segment],
        TASK,
        BLOCK,
        public_key_of(identity),
        [start_hash(segment.start)],
        not_before_ns=0,
    )
    assert result.ok


def test_manifest_round_trip_and_proof_hash(tmp_path: Path, identity):
    segment = _one_segment(tmp_path, identity, _log())
    manifest = task_manifest(TASK, ROBOT, [segment_part(segment, "aa" * 32, 123)], identity)
    on_chain = proof_hash(manifest)
    assert check_manifest(manifest, public_key_of(identity), on_chain).ok


def test_edited_manifest_fails(tmp_path: Path, identity):
    segment = _one_segment(tmp_path, identity, _log())
    manifest = task_manifest(TASK, ROBOT, [segment_part(segment, "aa" * 32, 123)], identity)
    on_chain = proof_hash(manifest)
    edited = copy.deepcopy(manifest)
    edited["segments"][0]["log"]["size"] = 124
    result = check_manifest(edited, public_key_of(identity), on_chain)
    assert (result.ok, result.reason) == (False, "manifest does not match proof_hash on the chain")
    resigned_hash = proof_hash(edited)
    result = check_manifest(edited, public_key_of(identity), resigned_hash)
    assert (result.ok, result.reason) == (False, "bad manifest signature")

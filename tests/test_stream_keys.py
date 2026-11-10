"""Throw-away keys against a robot hacked part-way through a task.

The hacker gets a perfect copy of the recorder at the moment of the hack. These tests pin down
what that copy can and cannot do, including the limits.
"""

from __future__ import annotations

import copy
from pathlib import Path

import pytest

from veriseal.stream import (
    EpochKeys,
    StreamSealer,
    _epoch_key,
    _next_seed,
    check_heads,
    check_log,
    epoch_checker,
    key_commitment,
    seal_stream,
    verify_stream,
)

SECOND = 1_000_000_000
TASK = "task-42"
KEYS = 12


def _log(count: int = 100) -> list[tuple[str, int, bytes]]:
    return [(f"/t{i % 3}", i * 100_000_000, i.to_bytes(4, "big")) for i in range(count)]


def _record_until_hack(messages):
    """Record up to the hack, which lands just as epoch 5 begins.

    Returns the keys' public half, the heads made so far, the honest recorder, and the
    hacker's copy of it.
    """
    keys = EpochKeys(KEYS)
    sealer = StreamSealer(TASK, SECOND, keys.sign)
    heads = []
    for topic, log_time, payload in messages[:51]:
        heads += sealer.add(topic, log_time, payload)[1]
    assert [head["epoch"] for head in heads] == [0, 1, 2, 3, 4]
    return keys.public_keys, heads, sealer, copy.deepcopy(sealer)


def test_honest_recording_passes(tmp_path: Path):
    keys = EpochKeys(KEYS)
    public_keys = keys.public_keys
    heads = seal_stream(_log(), TASK, SECOND, keys.sign, tmp_path / "h")
    assert verify_stream(_log(), heads, TASK, epoch_checker(public_keys)).ok


def test_each_epoch_needs_its_own_key(tmp_path: Path):
    keys = EpochKeys(KEYS)
    public_keys = keys.public_keys
    heads = seal_stream(_log(), TASK, SECOND, keys.sign, tmp_path / "h")
    shifted = [public_keys[1]] + public_keys[1:]
    assert check_heads(heads, TASK, epoch_checker(shifted)).reason == "bad signature"


def test_a_used_key_cannot_sign_again():
    keys = EpochKeys(KEYS)
    keys.sign(0, b"a")
    keys.sign(1, b"b")
    with pytest.raises(ValueError):
        keys.sign(0, b"forged")
    with pytest.raises(ValueError):
        keys.sign(1, b"forged")


def test_a_chain_runs_out():
    keys = EpochKeys(1)
    keys.sign(0, b"a")
    with pytest.raises(ValueError):
        keys.sign(1, b"b")


def test_keys_are_fixed_by_the_seed_and_differ_each_task():
    assert EpochKeys(3, b"\x01" * 32).public_keys == EpochKeys(3, b"\x01" * 32).public_keys
    assert EpochKeys(3).public_keys != EpochKeys(3).public_keys


def test_what_survives_the_hack_cannot_make_any_earlier_key():
    keys = EpochKeys(KEYS)
    for epoch in range(5):
        keys.sign(epoch, b"x")
    seed = bytes(keys._seed)
    reachable = set()
    for _ in range(100):
        reachable.add(_epoch_key(seed).public_key().public_bytes_raw())
        seed = _next_seed(seed)
    assert not reachable & set(keys.public_keys[:5])
    assert set(keys.public_keys[5:]) <= reachable


def test_hacker_cannot_change_the_past_and_keep_the_heads():
    messages = _log()
    public_keys, heads, _sealer, hacker = _record_until_hack(messages)
    forged = list(messages[:51])
    forged[25] = (forged[25][0], forged[25][1], b"forged")
    for topic, log_time, payload in messages[51:]:
        heads += hacker.add(topic, log_time, payload)[1]
    heads += hacker.finish()
    forged += messages[51:]
    assert check_heads(heads, TASK, epoch_checker(public_keys)).ok
    result = check_log(forged, heads)
    assert (result.ok, result.epoch) == (False, 2)


def test_hacker_cannot_re_sign_the_past():
    messages = _log()
    public_keys, heads, _sealer, hacker = _record_until_hack(messages)
    with pytest.raises(ValueError):
        hacker._signer(2, b"a new head for epoch 2")
    fresh = EpochKeys(KEYS)
    resealer = StreamSealer(TASK, SECOND, fresh.sign)
    forged_heads = []
    for topic, log_time, _payload in messages[:51]:
        forged_heads += resealer.add(topic, log_time, b"forged")[1]
    spliced = heads[:2] + forged_heads[2:]
    assert check_heads(spliced, TASK, epoch_checker(public_keys)).ok is False


def test_hacker_cannot_skip_the_epochs_it_cannot_sign():
    messages = _log()
    public_keys, heads, _sealer, hacker = _record_until_hack(messages)
    for topic, log_time, payload in messages[51:]:
        heads += hacker.add(topic, log_time, payload)[1]
    heads += hacker.finish()
    result = check_heads(heads[:2] + heads[5:], TASK, epoch_checker(public_keys))
    assert (result.ok, result.reason) == (False, "a head is missing or out of order")


def test_hacker_can_cut_the_end_but_it_shows_as_unfinished():
    """The limit of erasing keys. A cut can't be hidden, but on its own it looks like a crash."""
    messages = _log()
    public_keys, heads, *_ = _record_until_hack(messages)
    kept = heads[:3]
    result = check_heads(kept, TASK, epoch_checker(public_keys))
    assert (result.ok, result.reason) == (False, "the final head is missing")
    assert check_log(messages[: kept[-1]["tree_size"]], kept).ok


def test_everything_after_the_hack_can_be_faked():
    """The other limit: from the hack onwards the hacker signs whatever it likes."""
    messages = _log()
    public_keys, heads, _sealer, hacker = _record_until_hack(messages)
    fake = [(topic, log_time, b"fabricated") for topic, log_time, _ in messages[51:]]
    for topic, log_time, payload in fake:
        heads += hacker.add(topic, log_time, payload)[1]
    heads += hacker.finish()
    assert verify_stream(messages[:51] + fake, heads, TASK, epoch_checker(public_keys)).ok


def test_a_whole_new_key_chain_is_caught_only_by_the_start_commitment(tmp_path: Path):
    """Why the commitment has to leave the robot before the task starts."""
    published = key_commitment(EpochKeys(KEYS).public_keys)
    forged_keys = EpochKeys(KEYS)
    forged_public = forged_keys.public_keys
    fake = [(topic, log_time, b"fabricated") for topic, log_time, _ in _log()]
    heads = seal_stream(fake, TASK, SECOND, forged_keys.sign, tmp_path / "h")
    assert verify_stream(fake, heads, TASK, epoch_checker(forged_public)).ok
    assert key_commitment(forged_public) != published

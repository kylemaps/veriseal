"""The order rule: each epoch's messages, sorted by time, wherever they sit in the file."""

from __future__ import annotations

import random

import pytest

from veriseal.merkle import leaf_hash
from veriseal.stream import (
    EpochKeys,
    StreamSealer,
    check_heads,
    check_log,
    epoch_checker,
    read_leaves,
    seal_stream,
)

SECOND = 1_000_000_000
MS = 1_000_000
TASK = "task-42"
KEYS = 40


def _seal(messages, **options):
    keys = EpochKeys(KEYS, b"\x01" * 32)  # a fixed seed, so equal input gives equal heads
    sealer = StreamSealer(TASK, SECOND, keys.sign, **options)
    heads = []
    for message in messages:
        heads += sealer.add(*message)[1]
    heads += sealer.finish()
    assert check_heads(heads, TASK, epoch_checker(keys.public_keys)).ok
    return heads


def _log(count=40, start_ns=5 * SECOND):
    return [(f"/t{i % 3}", start_ns + i * SECOND // 10, i.to_bytes(4, "big")) for i in range(count)]


def test_messages_with_the_same_time_seal_the_same_either_way():
    tied = [("/a", 5 * SECOND, b"one"), ("/b", 5 * SECOND, b"two"), ("/a", 7 * SECOND, b"end")]
    reversed_ties = [tied[1], tied[0], tied[2]]
    assert _seal(tied) == _seal(reversed_ties)


def test_disorder_inside_one_epoch_is_absorbed():
    messages = _log()
    shuffled = messages[:10] + random.Random(1).sample(messages[10:20], 10) + messages[20:]
    assert _seal(shuffled) == _seal(messages)
    assert check_log(messages, _seal(shuffled)).ok


def test_reorder_allowance_holds_an_epoch_open():
    sealer = StreamSealer(TASK, SECOND, EpochKeys(KEYS).sign, reorder_ns=300 * MS)
    assert sealer.add("/t", 0, b"a")[1] == []
    assert sealer.add("/t", 1100 * MS, b"b")[1] == []
    assert sealer.add("/t", 950 * MS, b"c")[1] == []  # still epoch 0's: not late
    (head,) = sealer.add("/t", 1400 * MS, b"d")[1]
    assert (head["epoch"], head["tree_size"], head["late"]) == (0, 2, [])


def test_disorder_across_epochs_within_the_allowance_seals_like_sorted_input():
    messages = _log()
    jumbled = list(messages)
    jumbled[9], jumbled[10] = jumbled[10], jumbled[9]  # 5.9 s after 6.0 s, across a boundary
    assert _seal(jumbled, reorder_ns=200 * MS) == _seal(messages, reorder_ns=200 * MS)


def test_a_message_after_its_epoch_closed_is_listed_as_late():
    messages = _log()
    straggler = ("/t9", 6 * SECOND - 20 * MS, b"late")  # belongs to epoch 0, which has closed
    arrived = messages[:12] + [straggler] + messages[12:]
    heads = _seal(arrived)
    assert heads[1]["late"] == [leaf_hash(*straggler).hex()]
    result = check_log(arrived, heads)
    assert (result.ok, result.late_messages, result.max_late_ns) == (True, 1, 20 * MS)


def test_a_late_message_is_protected_from_the_epoch_that_sealed_it():
    messages = _log()
    straggler = ("/t9", 6 * SECOND - 20 * MS, b"late")
    heads = _seal(messages[:12] + [straggler] + messages[12:])
    changed = messages[:12] + [("/t9", straggler[1], b"edit")] + messages[12:]
    assert not check_log(changed, heads).ok


def test_a_message_before_the_first_one_is_late_in_epoch_0():
    early = ("/t9", 5 * SECOND - 30 * MS, b"early")
    messages = _log()
    heads = _seal([messages[0], early] + messages[1:])
    assert heads[0]["late"] == [leaf_hash(*early).hex()]
    assert check_log(messages + [early], heads).ok


def test_a_head_cannot_list_a_message_that_was_on_time():
    messages = _log()
    heads = _seal(messages)
    heads[1]["late"] = [leaf_hash(*messages[15]).hex()]  # stamped inside epoch 1 itself
    result = check_log(messages, heads)
    assert (result.ok, result.reason, result.epoch) == (
        False,
        "a message's time does not fit its epoch",
        1,
    )


@pytest.mark.parametrize(
    "late", [None, "ab" * 32, ["zz" * 32], ["AB" * 32], ["ab"], [7], [["ab" * 32]]]
)
def test_a_malformed_late_list_is_rejected(late):
    keys = EpochKeys(KEYS)
    sealer = StreamSealer(TASK, SECOND, keys.sign)
    heads = []
    for message in _log():
        heads += sealer.add(*message)[1]
    heads += sealer.finish()
    heads[2]["late"] = late
    result = check_heads(heads, TASK, epoch_checker(keys.public_keys))
    assert (result.ok, result.reason, result.epoch) == (False, "a head is malformed", 2)


def test_a_head_cannot_list_more_late_messages_than_it_adds():
    keys = EpochKeys(KEYS)
    heads = []
    sealer = StreamSealer(TASK, SECOND, keys.sign)
    for message in _log():
        heads += sealer.add(*message)[1]
    heads += sealer.finish()
    heads[2]["late"] = ["ab" * 32] * 11
    result = check_heads(heads, TASK, epoch_checker(keys.public_keys))
    assert result.reason == "a head lists more late messages than it adds"


def test_grace_delays_the_timer():
    sealer = StreamSealer(TASK, SECOND, EpochKeys(KEYS).sign, grace_ns=2 * SECOND)
    sealer.add("/t", 0, b"a")
    assert sealer.tick(2900 * MS) == []
    assert [head["epoch"] for head in sealer.tick(3 * SECOND)] == [0]


def test_a_given_origin_starts_the_timer_before_any_message():
    sealer = StreamSealer(TASK, SECOND, EpochKeys(KEYS).sign, origin_ns=0)
    assert [head["origin_ns"] for head in sealer.tick(2 * SECOND)] == [0, 0]


def test_finish_closes_epochs_that_are_still_waiting():
    sealer = StreamSealer(TASK, SECOND, EpochKeys(KEYS).sign, reorder_ns=2 * SECOND)
    messages = [("/t", 0, b"a"), ("/t", 1500 * MS, b"b"), ("/t", 2500 * MS, b"c")]
    for message in messages:
        assert sealer.add(*message)[1] == []
    heads = sealer.finish()
    assert [(h["epoch"], h["tree_size"], h["final"]) for h in heads] == [
        (0, 1, False),
        (1, 2, False),
        (2, 3, True),
    ]
    assert check_log(messages, heads).ok


def test_a_failed_save_inside_add_loses_nothing_when_the_message_is_added_again():
    keys = EpochKeys(KEYS)
    public_keys = keys.public_keys
    failures = [OSError("disk full")]

    def persist(head):
        if failures:
            raise failures.pop()

    sealer = StreamSealer(TASK, SECOND, keys.sign_only, persist=persist, erase=keys.erase)
    sealer.add("/t", 0, b"a")
    with pytest.raises(OSError):
        sealer.add("/t", SECOND, b"b")
    heads = sealer.add("/t", SECOND, b"b")[1] + sealer.finish()
    assert check_heads(heads, TASK, epoch_checker(public_keys)).ok
    assert check_log([("/t", 0, b"a"), ("/t", SECOND, b"b")], heads).ok


def test_the_sidecar_is_in_tree_order_and_names_messages_by_their_place_in_the_file(tmp_path):
    messages = _log()
    within = messages[:10] + messages[10:20][::-1] + messages[20:]  # epoch 1 written backwards
    keys = EpochKeys(KEYS)
    leaves_path = tmp_path / "leaves"
    heads = seal_stream(within, TASK, SECOND, keys.sign, tmp_path / "heads", leaves_path)
    leaves = read_leaves(leaves_path)
    assert leaves == [leaf_hash(*message) for message in messages]
    changed = list(within)
    changed[12] = (changed[12][0], changed[12][1], b"forged")
    result = check_log(changed, heads, leaves)
    assert (result.ok, result.epoch, result.message_index) == (False, 1, 12)

"""Signed checkpoints: every kind of change to the log or the heads must be caught."""

from __future__ import annotations

import copy
import random
from pathlib import Path

import pytest

from veriseal.merkle import consistency_proof, merkle_root, verify_consistency
from veriseal.signing import generate_key
from veriseal.stream import (
    check_heads,
    check_log,
    key_checker,
    key_signer,
    public_key_of,
    read_heads,
    read_leaves,
    seal_stream,
    verify_stream,
)

SECOND = 1_000_000_000
TASK = "task-42"


def _log(count: int = 100, step_ms: int = 100) -> list[tuple[str, int, bytes]]:
    return [
        (f"/topic{i % 3}", 5 * SECOND + i * step_ms * 1_000_000, i.to_bytes(4, "big"))
        for i in range(count)
    ]


@pytest.fixture
def sealed(tmp_path: Path):
    key = generate_key()
    messages = _log()
    heads_path, leaves_path = tmp_path / "log.heads.jsonl", tmp_path / "log.leaves"
    heads = seal_stream(messages, TASK, SECOND, key_signer(key), heads_path, leaves_path)
    return messages, heads, key_checker(public_key_of(key)), heads_path, leaves_path


def test_clean_log_passes(sealed):
    messages, heads, checker, *_ = sealed
    assert verify_stream(messages, heads, TASK, checker).ok


def test_files_round_trip(sealed):
    messages, heads, _checker, heads_path, leaves_path = sealed
    assert read_heads(heads_path) == heads
    assert len(read_leaves(leaves_path)) == len(messages)
    assert leaves_path.stat().st_size == 32 * len(messages)


def test_one_head_per_epoch_and_a_final_head(sealed):
    _messages, heads, *_ = sealed
    assert [h["epoch"] for h in heads] == list(range(10))
    assert [h["final"] for h in heads] == [False] * 9 + [True]
    assert heads[-1]["tree_size"] == 100


def test_quiet_epochs_still_get_heads(tmp_path: Path):
    key = generate_key()
    messages = [("/a", 0, b"1"), ("/a", 5 * SECOND, b"2")]
    heads = seal_stream(messages, TASK, SECOND, key_signer(key), tmp_path / "h")
    assert [h["tree_size"] for h in heads] == [1, 1, 1, 1, 1, 2]
    assert verify_stream(messages, heads, TASK, key_checker(public_key_of(key))).ok


def test_empty_log_passes(tmp_path: Path):
    key = generate_key()
    heads = seal_stream([], TASK, SECOND, key_signer(key), tmp_path / "h")
    assert verify_stream([], heads, TASK, key_checker(public_key_of(key))).ok


def test_changed_byte_names_the_epoch_and_the_message(sealed):
    messages, heads, checker, _heads_path, leaves_path = sealed
    for index in (0, 37, 99):
        changed = list(messages)
        topic, log_time, payload = changed[index]
        changed[index] = (topic, log_time, payload[:-1] + bytes([payload[-1] ^ 1]))
        result = verify_stream(changed, heads, TASK, checker, read_leaves(leaves_path))
        assert not result.ok
        assert result.epoch == index // 10
        assert result.message_index == index


def test_without_the_sidecar_only_the_epoch_is_named(sealed):
    messages, heads, checker, *_ = sealed
    changed = list(messages)
    changed[37] = (changed[37][0], changed[37][1], b"forged")
    result = verify_stream(changed, heads, TASK, checker)
    assert (result.ok, result.epoch, result.message_index) == (False, 3, None)


def test_forged_sidecar_is_not_believed(sealed):
    messages, heads, checker, _heads_path, leaves_path = sealed
    changed = list(messages)
    changed[37] = (changed[37][0], changed[37][1], b"forged")
    leaves = read_leaves(leaves_path)
    leaves[5] = b"\x00" * 32
    result = verify_stream(changed, heads, TASK, checker, leaves)
    assert (result.ok, result.epoch, result.message_index) == (False, 3, None)


def test_deleted_message_is_caught(sealed):
    messages, heads, checker, _heads_path, leaves_path = sealed
    result = verify_stream(
        messages[:40] + messages[41:], heads, TASK, checker, read_leaves(leaves_path)
    )
    assert not result.ok
    assert result.epoch == 4
    assert result.message_index == 40


def test_order_in_the_file_does_not_matter(sealed):
    """The seal fixes each message's topic, time and bytes; readers sort by time anyway."""
    messages, heads, checker, _heads_path, leaves_path = sealed
    shuffled = list(messages)
    random.Random(7).shuffle(shuffled)
    assert verify_stream(shuffled, heads, TASK, checker, read_leaves(leaves_path)).ok


def test_swapped_times_are_caught(sealed):
    messages, heads, checker, *_ = sealed
    swapped = list(messages)
    (topic_a, time_a, data_a), (topic_b, time_b, data_b) = swapped[12:14]
    swapped[12:14] = [(topic_a, time_b, data_a), (topic_b, time_a, data_b)]
    result = verify_stream(swapped, heads, TASK, checker)
    assert not result.ok
    assert result.epoch == 1


def test_cut_log_is_caught(sealed):
    messages, heads, checker, *_ = sealed
    result = verify_stream(messages[:55], heads, TASK, checker)
    assert (result.ok, result.reason) == (False, "log is missing messages")


def test_added_message_is_caught(sealed):
    messages, heads, checker, *_ = sealed
    extra = messages + [("/topic0", 99 * SECOND, b"late")]
    result = verify_stream(extra, heads, TASK, checker)
    assert (result.ok, result.reason) == (False, "log has messages after the final head")


def test_removed_middle_head_is_caught(sealed):
    messages, heads, checker, *_ = sealed
    result = verify_stream(messages, heads[:4] + heads[5:], TASK, checker)
    assert (result.ok, result.epoch) == (False, 4)


def test_cut_off_heads_are_caught(sealed):
    _messages, heads, checker, *_ = sealed
    result = check_heads(heads[:6], TASK, checker)
    assert (result.ok, result.reason) == (False, "the final head is missing")


def test_edited_head_fails_its_signature(sealed):
    _messages, heads, checker, *_ = sealed
    edited = copy.deepcopy(heads)
    edited[3]["tree_size"] += 1
    assert check_heads(edited, TASK, checker).reason == "bad signature"


def test_head_from_another_key_fails(sealed, tmp_path: Path):
    messages, _heads, _checker, *_ = sealed
    forged = seal_stream(messages, TASK, SECOND, key_signer(generate_key()), tmp_path / "f")
    pinned = key_checker(public_key_of(generate_key()))
    assert check_heads(forged, TASK, pinned).reason == "bad signature"


def test_heads_cannot_move_to_another_task(sealed):
    _messages, heads, checker, *_ = sealed
    assert check_heads(heads, "task-43", checker).reason == "head belongs to a different task"


def test_one_key_lets_a_hacked_robot_re_sign_everything(tmp_path: Path):
    """The baseline: with the single key, a rewritten log passes. This is why keys must change."""
    key = generate_key()
    rewritten = [(topic, time_ns, b"fabricated") for topic, time_ns, _ in _log()]
    heads = seal_stream(rewritten, TASK, SECOND, key_signer(key), tmp_path / "r")
    assert verify_stream(rewritten, heads, TASK, key_checker(public_key_of(key))).ok


def test_witness_can_check_growth_from_heads_and_proofs(sealed):
    _messages, heads, _checker, _heads_path, leaves_path = sealed
    leaves = read_leaves(leaves_path)
    for older, newer in zip(heads, heads[1:], strict=False):
        proof = consistency_proof(leaves[: newer["tree_size"]], older["tree_size"])
        assert verify_consistency(
            older["tree_size"],
            newer["tree_size"],
            bytes.fromhex(older["root"]),
            bytes.fromhex(newer["root"]),
            proof,
        )


def test_log_check_alone_matches_batch_root(sealed):
    messages, heads, _checker, _heads_path, leaves_path = sealed
    assert check_log(messages, heads).ok
    assert heads[-1]["root"] == merkle_root(read_leaves(leaves_path)).hex()

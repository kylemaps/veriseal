"""Known-vector tests for the RFC 6962 Merkle tree."""

from __future__ import annotations

import hashlib

from veriseal.merkle import leaf_hash, merkle_root


def _internal(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(b"\x01" + left + right).digest()


# ---------- leaf_hash ----------

def test_leaf_hash_deterministic():
    h1 = leaf_hash("/pose", 1_000_000, b"\x01")
    h2 = leaf_hash("/pose", 1_000_000, b"\x01")
    assert h1 == h2
    assert len(h1) == 32


def test_leaf_hash_differs_by_topic():
    assert leaf_hash("/a", 0, b"x") != leaf_hash("/b", 0, b"x")


def test_leaf_hash_differs_by_time():
    assert leaf_hash("/t", 1, b"x") != leaf_hash("/t", 2, b"x")


def test_leaf_hash_differs_by_payload():
    assert leaf_hash("/t", 0, b"\x00") != leaf_hash("/t", 0, b"\x01")


# ---------- merkle_root ----------

def test_empty_root():
    assert merkle_root([]) == hashlib.sha256(b"").digest()


def test_single_leaf_is_promoted():
    h = leaf_hash("/pose", 1_000_000, b"\x01")
    assert merkle_root([h]) == h


def test_two_leaves():
    l0 = leaf_hash("/pose", 1_000_000, b"\x01")
    l1 = leaf_hash("/status", 2_000_000, b"\xaa")
    expected = _internal(l0, l1)
    assert merkle_root([l0, l1]) == expected


def test_three_leaves_odd_promotion():
    """Third leaf is promoted unchanged at level 1."""
    l0 = leaf_hash("/pose", 1_000_000, b"\x01")
    l1 = leaf_hash("/status", 2_000_000, b"\xaa")
    l2 = leaf_hash("/pose", 3_000_000, b"\x02")
    # level 1: [internal(l0, l1), l2]
    # root:     internal(internal(l0, l1), l2)
    expected = _internal(_internal(l0, l1), l2)
    assert merkle_root([l0, l1, l2]) == expected


def test_four_leaves_balanced():
    l0 = leaf_hash("/t", 0, b"\x00")
    l1 = leaf_hash("/t", 1, b"\x01")
    l2 = leaf_hash("/t", 2, b"\x02")
    l3 = leaf_hash("/t", 3, b"\x03")
    expected = _internal(_internal(l0, l1), _internal(l2, l3))
    assert merkle_root([l0, l1, l2, l3]) == expected


def test_five_leaves():
    """n=5: k=4. MTH = internal(MTH([l0..l3]), l4)."""
    ls = [leaf_hash("/t", i, bytes([i])) for i in range(5)]
    # MTH([l0..l3]) = internal(internal(l0,l1), internal(l2,l3))
    left = _internal(_internal(ls[0], ls[1]), _internal(ls[2], ls[3]))
    expected = _internal(left, ls[4])
    assert merkle_root(ls) == expected


def test_seven_leaves():
    """n=7: k=4. MTH = internal(MTH([l0..l3]), MTH([l4..l6]))."""
    ls = [leaf_hash("/t", i, bytes([i])) for i in range(7)]
    # MTH([l0..l3])
    left = _internal(_internal(ls[0], ls[1]), _internal(ls[2], ls[3]))
    # MTH([l4..l6]): n=3 k=2 → internal(internal(l4,l5), l6)
    right = _internal(_internal(ls[4], ls[5]), ls[6])
    expected = _internal(left, right)
    assert merkle_root(ls) == expected


def test_root_changes_on_tamper():
    leaves = [leaf_hash("/t", i, bytes([i])) for i in range(4)]
    root1 = merkle_root(leaves)
    tampered = list(leaves)
    tampered[2] = leaf_hash("/t", 2, bytes([0xFF]))
    assert merkle_root(tampered) != root1

"""The growing tree must agree with the batch tree, and consistency proofs must hold."""

from __future__ import annotations

import hashlib
import random

import pytest

from veriseal.merkle import (
    IncrementalTree,
    consistency_proof,
    merkle_root,
    verify_consistency,
)


def _leaves(count: int, seed: int = 0) -> list[bytes]:
    rng = random.Random(seed)
    return [hashlib.sha256(rng.randbytes(16)).digest() for _ in range(count)]


def test_empty_tree_matches_batch_root():
    assert IncrementalTree().root() == merkle_root([])


def test_root_matches_batch_root_at_every_size():
    leaves = _leaves(300)
    tree = IncrementalTree()
    for count, leaf in enumerate(leaves, start=1):
        tree.append(leaf)
        assert tree.size == count
        assert tree.root() == merkle_root(leaves[:count])


def test_root_matches_batch_root_over_random_sequences():
    rng = random.Random(1)
    for seed in range(1000):
        leaves = _leaves(rng.randint(1, 80), seed)
        tree = IncrementalTree()
        for leaf in leaves:
            tree.append(leaf)
        assert tree.root() == merkle_root(leaves)


def test_memory_stays_logarithmic():
    tree = IncrementalTree()
    for leaf in _leaves(5000):
        tree.append(leaf)
    assert len(tree._peaks) <= 13


def test_changed_leaf_changes_root():
    leaves = _leaves(37)
    changed = list(leaves)
    changed[20] = hashlib.sha256(b"changed").digest()
    assert merkle_root(changed) != merkle_root(leaves)


def test_rfc_6962_proof_shape_for_seven_leaves():
    """Worked examples from RFC 6962 §2.1.3, with d0..d6 as the leaves."""
    d = _leaves(7)

    def mth(start: int, end: int) -> bytes:
        return merkle_root(d[start:end])

    assert consistency_proof(d, 3) == [d[2], d[3], mth(0, 2), mth(4, 7)]
    assert consistency_proof(d, 4) == [mth(4, 7)]
    assert consistency_proof(d, 6) == [mth(4, 6), d[6], mth(0, 4)]


def test_consistency_proofs_verify_for_all_small_sizes():
    leaves = _leaves(70)
    for new_size in range(1, 71):
        new_root = merkle_root(leaves[:new_size])
        for old_size in range(1, new_size + 1):
            proof = consistency_proof(leaves[:new_size], old_size)
            old_root = merkle_root(leaves[:old_size])
            assert verify_consistency(old_size, new_size, old_root, new_root, proof)


def test_consistency_fails_when_history_was_rewritten():
    leaves = _leaves(40)
    rewritten = list(leaves)
    rewritten[3] = hashlib.sha256(b"rewritten").digest()
    for old_size in range(4, 40):
        proof = consistency_proof(rewritten, old_size)
        old_root = merkle_root(leaves[:old_size])
        assert not verify_consistency(old_size, 40, old_root, merkle_root(rewritten), proof)


def test_consistency_fails_with_a_tampered_proof():
    leaves = _leaves(21)
    proof = consistency_proof(leaves, 9)
    proof[0] = hashlib.sha256(proof[0]).digest()
    assert not verify_consistency(9, 21, merkle_root(leaves[:9]), merkle_root(leaves), proof)


def test_consistency_rejects_bad_sizes():
    leaves = _leaves(5)
    with pytest.raises(ValueError):
        consistency_proof(leaves, 6)
    root = merkle_root(leaves)
    assert not verify_consistency(6, 5, root, root, [])
    assert verify_consistency(5, 5, root, root, [])
    assert not verify_consistency(5, 5, root, root, [root])

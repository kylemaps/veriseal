"""Known-answer + domain-separation guards for the leaf hash and Merkle tree.

These lock the wire format independently of the implementation: the expected
digests below were computed once from SPEC-manifest.md 2-3 and are hardcoded, so
a change to the leaf preimage layout, the RFC 6962 domain-separator prefixes, or
the topic length-prefix is caught even if someone edits both the code and its
inline recompute. A drifted hash silently breaks cross-verifier agreement (the
web verifier and panel reimplement this), which is why it is pinned here.
"""

from __future__ import annotations

import hashlib

from veriseal.merkle import leaf_hash, merkle_root

# ── Known answers (hardcoded; recompute only if the SPEC wire format changes) ──

_KA_LEAF_A_0_BC = "8fb9e04fb02cd05202f969ee619fdf99897c9868f4941faa1c632f0d3cda379e"
_KA_LEAF_AB_0_C = "8b888d87e1366ce1b1b1b5ff9b047a3ef0ec225f88ca9238bff7a5db2b1b7052"
_KA_ROOT_2 = "aba471f565038dd20860f60a496544f5beec6a8b57007b23f0991f023e3aab76"
_KA_EMPTY = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"


def test_leaf_hash_known_answer() -> None:
    assert leaf_hash("/a", 0, b"bc").hex() == _KA_LEAF_A_0_BC
    assert leaf_hash("/ab", 0, b"c").hex() == _KA_LEAF_AB_0_C


def test_merkle_root_known_answer() -> None:
    l0 = leaf_hash("/pose", 1, b"\x01")
    l1 = leaf_hash("/status", 2, b"\xaa")
    assert merkle_root([l0, l1]).hex() == _KA_ROOT_2


def test_empty_and_single_known_answer() -> None:
    assert merkle_root([]).hex() == _KA_EMPTY  # SHA-256(b"")
    h = leaf_hash("/x", 3, b"z")
    assert merkle_root([h]) == h  # single leaf returns the (already-hashed) leaf


# ── Domain separation: the topic length-prefix must disambiguate boundaries ──


def test_topic_length_prefix_prevents_collision() -> None:
    """Without the 4-byte topic length prefix, ('/a', b'bc') and ('/ab', b'c')
    would share a preimage tail and could collide. The length prefix keeps them
    distinct."""
    assert leaf_hash("/a", 0, b"bc") != leaf_hash("/ab", 0, b"c")


# ── Domain separation: the RFC 6962 leaf/internal prefixes are load-bearing ──


def test_leaf_prefix_0x00_is_part_of_the_hash() -> None:
    """The leaf hash is SHA-256(0x00 + preimage). Dropping the 0x00 prefix (or
    using a different one) must produce a different digest — pinning the domain
    separator independently of leaf_hash()."""
    topic, log_time, payload = "/pose", 7, b"\x09"
    topic_bytes = topic.encode("utf-8")
    preimage = (
        b"veriseal-leaf-v1\x00"
        + len(topic_bytes).to_bytes(4, "big")
        + topic_bytes
        + log_time.to_bytes(8, "big")
        + payload
    )
    with_prefix = hashlib.sha256(b"\x00" + preimage).digest()
    without_prefix = hashlib.sha256(preimage).digest()
    wrong_prefix = hashlib.sha256(b"\x01" + preimage).digest()
    assert leaf_hash(topic, log_time, payload) == with_prefix
    assert with_prefix != without_prefix
    assert with_prefix != wrong_prefix


def test_internal_node_prefix_0x01_is_part_of_the_hash() -> None:
    """Internal nodes are SHA-256(0x01 + left + right). A node computed without
    the 0x01 prefix, or with a leaf prefix, must differ from the real root —
    guarding against second-preimage attacks that RFC 6962 domain separation
    exists to prevent."""
    l0 = leaf_hash("/a", 1, b"x")
    l1 = leaf_hash("/b", 2, b"y")
    real = merkle_root([l0, l1])
    no_prefix = hashlib.sha256(l0 + l1).digest()
    leaf_prefixed = hashlib.sha256(b"\x00" + l0 + l1).digest()
    assert real == hashlib.sha256(b"\x01" + l0 + l1).digest()
    assert real != no_prefix
    assert real != leaf_prefixed

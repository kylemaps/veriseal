"""RFC 6962 Merkle tree over SHA-256 leaf hashes."""

from __future__ import annotations

import hashlib


def _leaf_preimage(topic: str, log_time_ns: int, payload: bytes) -> bytes:
    topic_bytes = topic.encode("utf-8")
    return (
        b"veriseal-leaf-v1\x00"
        + len(topic_bytes).to_bytes(4, "big")
        + topic_bytes
        + log_time_ns.to_bytes(8, "big")
        + payload
    )


def leaf_hash(topic: str, log_time_ns: int, payload: bytes) -> bytes:
    """SHA-256 of the domain-separated leaf preimage (RFC 6962: 0x00 prefix)."""
    return hashlib.sha256(b"\x00" + _leaf_preimage(topic, log_time_ns, payload)).digest()


def _internal(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(b"\x01" + left + right).digest()


def _split(n: int) -> int:
    """Largest power of two strictly less than n (RFC 6962 §2.1)."""
    return 1 << ((n - 1).bit_length() - 1)


def merkle_root(leaf_hashes: list[bytes]) -> bytes:
    """
    Recursive Merkle Tree Hash per RFC 6962 §2.1.

    Inputs are already leaf hashes (computed with the 0x00-prefix domain separator).

      MTH([])   = SHA-256(b"")
      MTH([h])  = h                               (leaf already hashed)
      MTH(D[n]) = _internal(MTH(D[:k]), MTH(D[k:]))
                  where k = largest power of 2 strictly less than n
    """
    n = len(leaf_hashes)
    if n == 0:
        return hashlib.sha256(b"").digest()
    if n == 1:
        return leaf_hashes[0]
    k = _split(n)
    return _internal(merkle_root(leaf_hashes[:k]), merkle_root(leaf_hashes[k:]))


class IncrementalTree:
    """RFC 6962 tree that grows one leaf at a time, in arrival order.

    Keeps only the roots of its complete subtrees, about log2(n) hashes, so a recorder can
    produce the current root at any moment without holding the log. For the same leaves in
    the same order, ``root()`` equals ``merkle_root()``.
    """

    def __init__(self) -> None:
        self.size = 0
        self._peaks: list[tuple[int, bytes]] = []  # (leaf count, subtree root), largest first

    def append(self, leaf: bytes) -> None:
        count, node = 1, leaf
        while self._peaks and self._peaks[-1][0] == count:
            left_count, left = self._peaks.pop()
            count, node = left_count + count, _internal(left, node)
        self._peaks.append((count, node))
        self.size += 1

    def copy(self) -> IncrementalTree:
        other = IncrementalTree()
        other.size, other._peaks = self.size, list(self._peaks)
        return other

    def root(self) -> bytes:
        if not self._peaks:
            return merkle_root([])
        node = self._peaks[-1][1]
        for _count, left in reversed(self._peaks[:-1]):
            node = _internal(left, node)
        return node


def _subproof(old_size: int, leaves: list[bytes], complete: bool) -> list[bytes]:
    n = len(leaves)
    if old_size == n:
        return [] if complete else [merkle_root(leaves)]
    k = _split(n)
    if old_size <= k:
        return _subproof(old_size, leaves[:k], complete) + [merkle_root(leaves[k:])]
    return _subproof(old_size - k, leaves[k:], False) + [merkle_root(leaves[:k])]


def consistency_proof(leaves: list[bytes], old_size: int) -> list[bytes]:
    """Proof that the tree over ``leaves[:old_size]`` is the start of the tree over ``leaves``.

    Follows RFC 6962 §2.1.2. A witness holding only the two roots can check it.
    """
    if not 0 <= old_size <= len(leaves):
        raise ValueError("old_size must be between 0 and the number of leaves")
    if old_size == 0:
        return []
    return _subproof(old_size, leaves, True)


def verify_consistency(
    old_size: int, new_size: int, old_root: bytes, new_root: bytes, proof: list[bytes]
) -> bool:
    """Check a consistency proof, following RFC 9162 §2.1.4.2."""
    if old_size > new_size:
        return False
    if old_size == new_size:
        return not proof and old_root == new_root
    if old_size == 0:
        return not proof
    path = list(proof)
    if old_size & (old_size - 1) == 0:
        path.insert(0, old_root)
    if not path:
        return False
    fn, sn = old_size - 1, new_size - 1
    while fn & 1:
        fn >>= 1
        sn >>= 1
    fr = sr = path[0]
    for node in path[1:]:
        if sn == 0:
            return False
        if fn & 1 or fn == sn:
            fr, sr = _internal(node, fr), _internal(node, sr)
            while not fn & 1 and fn != 0:
                fn >>= 1
                sn >>= 1
        else:
            sr = _internal(sr, node)
        fn >>= 1
        sn >>= 1
    return sn == 0 and fr == old_root and sr == new_root

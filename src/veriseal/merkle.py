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

    Inputs are ALREADY leaf hashes (computed with the 0x00-prefix domain separator).

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

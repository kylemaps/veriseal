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


def merkle_root(leaves: list[bytes]) -> bytes:
    """
    Build a Merkle root over *leaves* using RFC 6962 rules:
      - empty  -> sha256(b"")
      - single -> the leaf itself (promoted)
      - odd node at any level is promoted unchanged
    """
    if not leaves:
        return hashlib.sha256(b"").digest()
    nodes: list[bytes] = list(leaves)
    while len(nodes) > 1:
        next_level: list[bytes] = []
        for i in range(0, len(nodes), 2):
            if i + 1 < len(nodes):
                next_level.append(_internal(nodes[i], nodes[i + 1]))
            else:
                next_level.append(nodes[i])
        nodes = next_level
    return nodes[0]

"""Build the veriseal manifest dict (schema version 1)."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import veriseal
from veriseal.canonical import canonical_json
from veriseal.merkle import leaf_hash, merkle_root
from veriseal.signing import public_pem, sign


def build_manifest(
    path: Path,
    messages: list[tuple[str, int, bytes]],
    file_sha256: str,
    file_size: int,
    key: Ed25519PrivateKey,
    created_utc: datetime | None = None,
    source_format: str = "mcap",
) -> dict:
    """
    Construct and sign the veriseal manifest.

    Leaf ordering: (log_time_ns, topic, leaf_hash_hex) ascending.
    Signed payload = canonical_json(manifest without 'signature' and 'anchor' keys).
    """
    if created_utc is None:
        created_utc = datetime.now(UTC)

    # Build and sort leaves
    raw_leaves = [
        {
            "topic": topic,
            "log_time": log_time_ns,
            "leaf_hash": leaf_hash(topic, log_time_ns, payload).hex(),
        }
        for topic, log_time_ns, payload in messages
    ]
    sorted_leaves = sorted(
        raw_leaves, key=lambda item: (item["log_time"], item["topic"], item["leaf_hash"])
    )
    leaves_with_index = [{"index": i, **leaf} for i, leaf in enumerate(sorted_leaves)]

    # Merkle root over sorted leaf hashes
    sorted_hashes = [bytes.fromhex(leaf["leaf_hash"]) for leaf in sorted_leaves]
    root = merkle_root(sorted_hashes)

    log_times = [item["log_time"] for item in sorted_leaves]

    manifest: dict = {
        "schema_version": "veriseal-manifest-v1",
        "tool_version": veriseal.__version__,
        "created_utc": created_utc.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "source": {
            "filename": path.name,
            "format": source_format,
            "sha256": file_sha256,
            "size_bytes": file_size,
        },
        "messages": {
            "count": len(messages),
            "log_time_min": min(log_times) if log_times else 0,
            "log_time_max": max(log_times) if log_times else 0,
        },
        "hash_alg": "SHA-256",
        "merkle": {
            "scheme": "RFC6962-SHA256",
            "root": root.hex(),
            "ordering": "log_time,topic,leaf_hash asc",
        },
        "leaves": leaves_with_index,
    }

    # Sign over canonical JSON (signature + anchor are not yet present)
    signed_payload = canonical_json(manifest)
    sig_bytes = sign(key, signed_payload)

    manifest["signature"] = {
        "alg": "Ed25519",
        "public_key": public_pem(key),
        "value": sig_bytes.hex(),
    }
    manifest["anchor"] = None

    return manifest

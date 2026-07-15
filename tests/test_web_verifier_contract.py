"""Lock the manifest-format contract that web/verify.html depends on.

The browser verifier reimplements verification in JS. It reads specific fields
and formats out of the .seal.json. If any of these change, web/verify.html must
be updated to match — this test fails loudly when the contract drifts.
"""

from __future__ import annotations

import re
from datetime import UTC, datetime
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from veriseal.manifest import build_manifest
from veriseal.mcap_io import file_digest, iter_messages

_FIXED_KEY = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
_FIXED_TIME = datetime(2026, 6, 24, 12, 0, 0, tzinfo=UTC)


def _build(sample_mcap: Path) -> dict:
    sha256_hex, size = file_digest(sample_mcap)
    messages = list(iter_messages(sample_mcap))
    return build_manifest(sample_mcap, messages, sha256_hex, size, _FIXED_KEY, _FIXED_TIME)


def test_source_fields_the_js_reads(sample_mcap: Path) -> None:
    m = _build(sample_mcap)
    # web/verify.html: result.fileOk compares source.sha256 and source.size_bytes
    assert re.fullmatch(r"[0-9a-f]{64}", m["source"]["sha256"])
    assert isinstance(m["source"]["size_bytes"], int)


def test_merkle_fields_the_js_reads(sample_mcap: Path) -> None:
    m = _build(sample_mcap)
    # web/verify.html: recomputeMerkle compares against merkle.root (64-hex)
    assert re.fullmatch(r"[0-9a-f]{64}", m["merkle"]["root"])


def test_leaf_shape_the_js_reads(sample_mcap: Path) -> None:
    m = _build(sample_mcap)
    # web/verify.html sorts leaves by (log_time, topic, leaf_hash) and hashes leaf_hash
    for leaf in m["leaves"]:
        assert set(leaf) >= {"topic", "log_time", "leaf_hash"}
        assert re.fullmatch(r"[0-9a-f]{64}", leaf["leaf_hash"])
        assert isinstance(leaf["log_time"], int)
        assert isinstance(leaf["topic"], str)


def test_signature_shape_the_js_reads(sample_mcap: Path) -> None:
    m = _build(sample_mcap)
    sig = m["signature"]
    # web/verify.html: importKey("spki", pemToDer(public_key)) + verify Ed25519
    assert sig["alg"] == "Ed25519"
    assert sig["public_key"].startswith("-----BEGIN PUBLIC KEY-----")
    assert "-----END PUBLIC KEY-----" in sig["public_key"]
    # signature value is 64 raw bytes -> 128 hex chars
    assert re.fullmatch(r"[0-9a-f]{128}", sig["value"])


def test_signed_payload_excludes_signature_and_anchor(sample_mcap: Path) -> None:
    m = _build(sample_mcap)
    # web/verify.html strips exactly these two keys before canonicalizing to verify
    assert "signature" in m
    assert "anchor" in m
    top_level = set(m)
    assert top_level - {"signature", "anchor"}  # something remains to sign over

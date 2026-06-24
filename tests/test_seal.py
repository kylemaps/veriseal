"""Integration tests for the seal pipeline (hermetic, no network)."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from veriseal.canonical import canonical_json
from veriseal.manifest import build_manifest
from veriseal.mcap_io import file_digest, iter_messages
from veriseal.signing import verify

# Fixed 32-byte seed — deterministic key for all seal tests.
_SEED = bytes(range(32))
_FIXED_KEY = Ed25519PrivateKey.from_private_bytes(_SEED)
_FIXED_TIME = datetime(2026, 6, 24, 12, 0, 0, tzinfo=UTC)


def _build(sample_mcap: Path) -> dict:
    sha256_hex, size = file_digest(sample_mcap)
    messages = list(iter_messages(sample_mcap))
    return build_manifest(sample_mcap, messages, sha256_hex, size, _FIXED_KEY, _FIXED_TIME)


def test_leaf_count_equals_message_count(sample_mcap: Path) -> None:
    manifest = _build(sample_mcap)
    assert len(manifest["leaves"]) == manifest["messages"]["count"]
    assert manifest["messages"]["count"] == 5


def test_seal_is_deterministic(sample_mcap: Path) -> None:
    """Two seals of the same file with the same key and timestamp must produce identical roots."""
    m1 = _build(sample_mcap)
    m2 = _build(sample_mcap)
    assert m1["merkle"]["root"] == m2["merkle"]["root"]


def test_leaf_ordering(sample_mcap: Path) -> None:
    manifest = _build(sample_mcap)
    leaves = manifest["leaves"]
    keys = [(leaf["log_time"], leaf["topic"], leaf["leaf_hash"]) for leaf in leaves]
    assert keys == sorted(keys)


def test_leaf_indices_sequential(sample_mcap: Path) -> None:
    manifest = _build(sample_mcap)
    assert [leaf["index"] for leaf in manifest["leaves"]] == list(range(5))


def test_signature_verifies(sample_mcap: Path) -> None:
    manifest = _build(sample_mcap)
    # Recompute the signed payload (manifest without signature + anchor)
    payload_dict = {k: v for k, v in manifest.items() if k not in ("signature", "anchor")}
    signed_payload = canonical_json(payload_dict)
    pub_pem_str = manifest["signature"]["public_key"]
    sig_bytes = bytes.fromhex(manifest["signature"]["value"])
    assert verify(pub_pem_str, signed_payload, sig_bytes)


def test_signature_fails_on_tamper(sample_mcap: Path) -> None:
    manifest = _build(sample_mcap)
    payload_dict = {k: v for k, v in manifest.items() if k not in ("signature", "anchor")}
    tampered = dict(payload_dict)
    tampered["messages"] = dict(tampered["messages"])
    tampered["messages"]["count"] = 999
    tampered_payload = canonical_json(tampered)
    pub_pem_str = manifest["signature"]["public_key"]
    sig_bytes = bytes.fromhex(manifest["signature"]["value"])
    assert not verify(pub_pem_str, tampered_payload, sig_bytes)


def test_manifest_canonical_json_roundtrip(sample_mcap: Path) -> None:
    """File written via canonical_json must parse back to an identical dict."""
    manifest = _build(sample_mcap)
    serialised = canonical_json(manifest)
    reparsed = json.loads(serialised)
    assert reparsed == manifest


def test_manifest_schema_fields(sample_mcap: Path) -> None:
    m = _build(sample_mcap)
    assert m["schema_version"] == "veriseal-manifest-v1"
    assert m["hash_alg"] == "SHA-256"
    assert m["merkle"]["scheme"] == "RFC6962-SHA256"
    assert m["merkle"]["ordering"] == "log_time,topic,leaf_hash asc"
    assert m["signature"]["alg"] == "Ed25519"
    assert m["anchor"] is None
    assert m["created_utc"] == "2026-06-24T12:00:00Z"


def test_seal_command_writes_files(sample_mcap: Path) -> None:
    """Smoke-test the seal() function: check it writes .seal.json and .key.pem."""
    from veriseal.seal import seal

    out_path = sample_mcap.parent / "out.seal.json"
    seal(sample_mcap, key_path=None, out_path=out_path)
    assert out_path.exists()
    manifest = json.loads(out_path.read_bytes())
    assert manifest["messages"]["count"] == 5
    # key.pem is written next to the mcap (same directory)
    key_path = sample_mcap.with_suffix("").with_suffix(".key.pem")
    assert key_path.exists()

"""Integration tests for the seal pipeline (hermetic, no network)."""

from __future__ import annotations

import json
import os
import tracemalloc
from datetime import UTC, datetime
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from veriseal.canonical import canonical_json
from veriseal.manifest import build_manifest
from veriseal.mcap_io import file_digest, iter_messages
from veriseal.seal import seal
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
    """Smoke-test the seal() function: it writes the .seal.json and the requested new key."""
    from veriseal.signing import load_private_pem, public_pem

    out_path = sample_mcap.parent / "out.seal.json"
    key_path = sample_mcap.parent / "signer.key.pem"
    seal(sample_mcap, new_key_path=key_path, out_path=out_path, do_anchor=False)
    manifest = json.loads(out_path.read_bytes())
    assert manifest["messages"]["count"] == 5
    assert manifest["signature"]["public_key"] == public_pem(load_private_pem(key_path))


# ── memory: payloads are hashed as they are read, never all held at once ─────


def test_build_manifest_streams_payloads(sample_mcap: Path) -> None:
    """50 MB of payloads from a generator must not all be held in memory at once."""

    def messages():
        for i in range(50):
            yield "/camera", 1_000_000 + i, os.urandom(1_000_000)

    tracemalloc.start()
    try:
        manifest = build_manifest(sample_mcap, messages(), "00" * 32, 1, _FIXED_KEY, _FIXED_TIME)
        peak = tracemalloc.get_traced_memory()[1]
    finally:
        tracemalloc.stop()
    assert manifest["messages"]["count"] == 50
    assert peak < 10_000_000, f"peak {peak / 1e6:.0f} MB: payloads were retained"


def test_build_manifest_is_the_same_from_a_list_or_a_generator(sample_mcap: Path) -> None:
    messages = list(iter_messages(sample_mcap))
    from_list = build_manifest(sample_mcap, messages, "00" * 32, 1, _FIXED_KEY, _FIXED_TIME)
    from_gen = build_manifest(sample_mcap, iter(messages), "00" * 32, 1, _FIXED_KEY, _FIXED_TIME)
    assert from_list == from_gen


def test_unreadable_log_leaves_no_new_key(tmp_path: Path) -> None:
    broken = tmp_path / "broken.mcap"
    broken.write_bytes(b"\x89MCAP0\r\n" + b"\x00" * 64)
    key = tmp_path / "new.key.pem"
    with pytest.raises(Exception):  # noqa: B017 - any read error; the point is the key file
        seal(broken, new_key_path=key, out_path=tmp_path / "s.seal.json", do_anchor=False)
    assert not key.exists()


def test_seal_and_verify_memory_does_not_grow_with_the_log(tmp_path: Path) -> None:
    """A 60 MB log of 1 MB messages: sealing and verifying it peak far below 60 MB."""
    from mcap.writer import CompressionType, Writer

    from veriseal.verify import run_verification

    log = tmp_path / "camera.mcap"
    frame = os.urandom(1_000_000)
    with open(log, "wb") as f:
        writer = Writer(f, compression=CompressionType.NONE)
        writer.start()
        schema = writer.register_schema(name="raw", encoding="", data=b"")
        cam = writer.register_channel(topic="/camera", message_encoding="", schema_id=schema)
        for i in range(60):
            t = 1_000_000_000 + i
            writer.add_message(channel_id=cam, log_time=t, publish_time=t, data=frame + bytes([i]))
        writer.finish()
    seal_path = tmp_path / "camera.seal.json"

    tracemalloc.start()
    try:
        seal(log, new_key_path=tmp_path / "k.pem", out_path=seal_path, do_anchor=False)
        seal_peak = tracemalloc.get_traced_memory()[1]
        tracemalloc.reset_peak()
        result = run_verification(log, json.loads(seal_path.read_bytes()))
        verify_peak = tracemalloc.get_traced_memory()[1]
    finally:
        tracemalloc.stop()
    assert result.ok
    assert seal_peak < 20_000_000, f"seal peaked at {seal_peak / 1e6:.0f} MB"
    assert verify_peak < 20_000_000, f"verify peaked at {verify_peak / 1e6:.0f} MB"

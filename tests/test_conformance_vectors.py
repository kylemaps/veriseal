"""The published conformance vectors must keep producing their documented results.

`conformance/` exists so a third party can implement SPEC-manifest.md without this
codebase. That promise only holds if the vectors and the results documented in
`conformance/README.md` stay true, so CI checks them here rather than trusting the
prose.

These are also the only tests that verify against a COMMITTED log file. Every other
test writes a fresh MCAP at run time, which means the file-digest check (SPEC 7
step 2) and leaf re-derivation (step 3) were never exercised against a fixed,
published artifact until now.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

from veriseal.canonical import canonical_json
from veriseal.verify import run_verification, verify_seal

CONFORMANCE = Path(__file__).resolve().parent.parent / "conformance"

# Documented in conformance/README.md — changing either means the published vectors
# changed, which is a breaking change for anyone who implemented against them.
MCAP_ROOT = "9a75174f04a956e947427887468f63381b3914cafbc3f83b052620a2bc04a581"
MCAP_SHA256 = "f8e502bce22c7130ccd70aaadef1e651a72296b93a7be9ace6c665e9993d1651"
BAG_ROOT = "0ea10129c602fb8f16edd2692117cbb9d52381c916224b758785e3b16be9208b"

# The tampered vector's documented localisation.
TAMPERED_TOPIC = "/status"
TAMPERED_LOG_TIME = 1_700_000_000_200_000_000


# ── MCAP vector ──────────────────────────────────────────────────────────────


def test_mcap_vector_is_intact() -> None:
    assert verify_seal(CONFORMANCE / "sample_ros1.mcap", CONFORMANCE / "sample_ros1.seal.json") == 0


def test_mcap_vector_matches_documented_digest_and_root() -> None:
    manifest = json.loads((CONFORMANCE / "sample_ros1.seal.json").read_bytes())
    assert manifest["source"]["sha256"] == MCAP_SHA256
    assert manifest["merkle"]["root"] == MCAP_ROOT
    assert manifest["messages"]["count"] == 10


def test_mcap_vector_is_the_cross_core_fixture() -> None:
    """Byte-identical to the manifest both JS verifier cores are pinned to.

    If these two ever diverge, the Python suite and the JS suites are silently
    testing different things.
    """
    panel_fixture = (
        Path(__file__).resolve().parent.parent
        / "veriseal-panel"
        / "test"
        / "fixtures"
        / "sample.seal.json"
    )
    if not panel_fixture.is_file():
        pytest.skip("panel fixtures are not shipped in the sdist (source checkout only)")
    assert (CONFORMANCE / "sample_ros1.seal.json").read_bytes() == panel_fixture.read_bytes()


def test_mcap_vector_has_no_source_format_key() -> None:
    """Backward-compat vector: a v1 manifest predating `source.format` must verify.

    Documented in conformance/README.md; a verifier that started REQUIRING
    source.format would break every manifest sealed before 2026-07-20.
    """
    manifest = json.loads((CONFORMANCE / "sample_ros1.seal.json").read_bytes())
    assert "format" not in manifest["source"]
    assert manifest["anchor"] is None


# ── tampered vector ──────────────────────────────────────────────────────────


def test_tampered_vector_is_tampered() -> None:
    assert (
        verify_seal(
            CONFORMANCE / "sample_ros1.tampered.mcap", CONFORMANCE / "sample_ros1.seal.json"
        )
        == 1
    )


def test_tampered_vector_fails_all_three_documented_checks() -> None:
    manifest = json.loads((CONFORMANCE / "sample_ros1.seal.json").read_bytes())
    result = run_verification(CONFORMANCE / "sample_ros1.tampered.mcap", manifest)

    assert result.sig_ok, "the manifest itself is untouched; only the log was altered"
    assert not result.source_ok, "source digest must mismatch"
    assert not result.root_ok, "merkle root must mismatch"
    assert result.actual_sha256 != MCAP_SHA256


def test_tampered_vector_localises_the_changed_message() -> None:
    """SPEC 7 step 8: naming WHICH message changed, not merely that one did."""
    manifest = json.loads((CONFORMANCE / "sample_ros1.seal.json").read_bytes())
    result = run_verification(CONFORMANCE / "sample_ros1.tampered.mcap", manifest)

    assert result.modifications == [(TAMPERED_TOPIC, TAMPERED_LOG_TIME)]
    assert result.removals == []
    assert result.additions == []


# ── ROS 1 bag vector (needs the optional reader) ─────────────────────────────

pytest.importorskip("rosbags", reason="ROS 1 vector needs veriseal[ros1]")


def test_bag_vector_is_intact_when_pinned() -> None:
    """The bag vector ships its public key, so it exercises SPEC 8 pinning."""
    assert (
        verify_seal(
            CONFORMANCE / "sample.bag",
            CONFORMANCE / "sample.bag.seal.json",
            pubkey_path=CONFORMANCE / "sample.bag.pub.pem",
        )
        == 0
    )


def test_bag_vector_records_rosbag1_format() -> None:
    manifest = json.loads((CONFORMANCE / "sample.bag.seal.json").read_bytes())
    assert manifest["source"]["format"] == "rosbag1"
    assert manifest["merkle"]["root"] == BAG_ROOT
    assert manifest["messages"]["count"] == 10


def test_bag_vector_is_reproducible_from_the_published_seed() -> None:
    """Re-sealing with the documented seed and timestamp must be byte-identical.

    This is what makes the vector a vector: anyone can regenerate it. If this
    fails, either the seed/time in conformance/README.md is wrong or something
    in the manifest construction stopped being deterministic.
    """
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    from veriseal.formats import detect_format, iter_messages
    from veriseal.manifest import build_manifest
    from veriseal.mcap_io import file_digest

    bag = CONFORMANCE / "sample.bag"
    key = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
    when = datetime(2026, 7, 20, 12, 0, 0, tzinfo=UTC)

    sha256_hex, size = file_digest(bag)
    rebuilt = build_manifest(
        bag,
        list(iter_messages(bag)),
        sha256_hex,
        size,
        key,
        when,
        source_format=detect_format(bag),
    )
    assert canonical_json(rebuilt) == (CONFORMANCE / "sample.bag.seal.json").read_bytes()

"""Tests for the trust-model features: --pubkey pin and --require-anchor."""

from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path
from unittest.mock import patch

import pytest
from mcap.writer import Writer

from veriseal.canonical import canonical_json
from veriseal.seal import seal
from veriseal.signing import generate_key, public_pem
from veriseal.verify import verify_seal

# ── shared fixture ───────────────────────────────────────────────────────────


def _write_mcap(path: Path, messages: list[tuple[str, int, bytes]]) -> Path:
    topics = sorted({t for t, _, _ in messages})
    with open(path, "wb") as f:
        writer = Writer(f)
        writer.start()
        schema_id = writer.register_schema(name="raw", encoding="", data=b"")
        ch = {
            t: writer.register_channel(topic=t, message_encoding="", schema_id=schema_id)
            for t in topics
        }
        for topic, log_time, data in messages:
            writer.add_message(
                channel_id=ch[topic], log_time=log_time, data=data, publish_time=log_time
            )
        writer.finish()
    return path


_MSGS = [("/pose", 1_000_000, b"\x01"), ("/pose", 2_000_000, b"\x02")]


@pytest.fixture
def sealed_pair(tmp_path: Path) -> tuple[Path, Path]:
    mcap = _write_mcap(tmp_path / "orig.mcap", _MSGS)
    seal_path = tmp_path / "orig.seal.json"
    seal(mcap, new_key_path=mcap.with_suffix(".key.pem"), out_path=seal_path, do_anchor=False)
    return mcap, seal_path


# ── --pubkey tests ───────────────────────────────────────────────────────────


def test_pubkey_correct_key_passes(sealed_pair: tuple[Path, Path], tmp_path: Path) -> None:
    """Passing the correct public key should not change the INTACT result."""
    mcap, seal_path = sealed_pair
    manifest = json.loads(seal_path.read_bytes())
    pub_path = tmp_path / "correct.pub.pem"
    pub_path.write_text(manifest["signature"]["public_key"])
    assert verify_seal(mcap, seal_path, pubkey_path=pub_path) == 0


def test_pubkey_wrong_key_fails(sealed_pair: tuple[Path, Path], tmp_path: Path) -> None:
    """Passing a different public key must return exit 1 (key mismatch)."""
    mcap, seal_path = sealed_pair
    wrong_key = generate_key()
    wrong_pub_path = tmp_path / "wrong.pub.pem"
    wrong_pub_path.write_text(public_pem(wrong_key))
    assert verify_seal(mcap, seal_path, pubkey_path=wrong_pub_path) == 1


def test_pubkey_non_ed25519_returns_2(sealed_pair: tuple[Path, Path], tmp_path: Path) -> None:
    """A non-Ed25519 key file passed as --pubkey must return exit 2 (error)."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.rsa import generate_private_key

    mcap, seal_path = sealed_pair
    rsa_key = generate_private_key(65537, 2048)
    rsa_pub_path = tmp_path / "rsa.pub.pem"
    rsa_pub_path.write_bytes(
        rsa_key.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )
    assert verify_seal(mcap, seal_path, pubkey_path=rsa_pub_path) == 2


# ── unpinned verify: exit 3 unless --allow-unpinned ──────────────────────────


def _out(capsys: pytest.CaptureFixture[str]) -> str:
    return " ".join(capsys.readouterr().out.split())


def test_unpinned_intact_exits_3(
    sealed_pair: tuple[Path, Path], capsys: pytest.CaptureFixture[str]
) -> None:
    """Trusting the embedded key means a re-seal by anyone passes, so it is not a clean 0."""
    mcap, seal_path = sealed_pair
    assert verify_seal(mcap, seal_path) == 3
    out = _out(capsys)
    assert "INTACT (signer not pinned): signature valid" in out
    assert "Exit code 3" in out


def test_allow_unpinned_exits_0(
    sealed_pair: tuple[Path, Path], capsys: pytest.CaptureFixture[str]
) -> None:
    mcap, seal_path = sealed_pair
    assert verify_seal(mcap, seal_path, allow_unpinned=True) == 0
    out = _out(capsys)
    assert "INTACT (signer not pinned)" in out  # still says so
    assert "Exit code 3" not in out


def test_pinned_intact_has_no_unpinned_note(
    sealed_pair: tuple[Path, Path], tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    mcap, seal_path = sealed_pair
    pub_path = tmp_path / "signer.pub.pem"
    pub_path.write_text(json.loads(seal_path.read_bytes())["signature"]["public_key"])
    assert verify_seal(mcap, seal_path, pubkey_path=pub_path) == 0
    out = _out(capsys)
    assert "INTACT: signature valid" in out
    assert "not pinned" not in out


def test_tampered_unpinned_still_exits_1(sealed_pair: tuple[Path, Path], tmp_path: Path) -> None:
    _, seal_path = sealed_pair
    other = _write_mcap(tmp_path / "other.mcap", [("/pose", 1_000_000, b"\xff")])
    assert verify_seal(other, seal_path) == 1
    assert verify_seal(other, seal_path, allow_unpinned=True) == 1


def test_cli_exit_codes_for_pinning(sealed_pair: tuple[Path, Path], tmp_path: Path) -> None:
    from typer.testing import CliRunner

    from veriseal.cli import app

    mcap, seal_path = sealed_pair
    runner = CliRunner()
    assert runner.invoke(app, ["verify", str(mcap), str(seal_path)]).exit_code == 3
    allowed = runner.invoke(app, ["verify", str(mcap), str(seal_path), "--allow-unpinned"])
    assert allowed.exit_code == 0
    packed = runner.invoke(app, ["pack", str(mcap), str(seal_path), "--out", str(tmp_path / "p")])
    assert packed.exit_code == 0  # the pack's exit code is unchanged; its message says it
    assert "signer not pinned" in " ".join(packed.stdout.split())


# ── --require-anchor tests ───────────────────────────────────────────────────


def test_require_anchor_fails_on_null_anchor(sealed_pair: tuple[Path, Path]) -> None:
    """Seal with --no-anchor (anchor=null); --require-anchor must return 1."""
    mcap, seal_path = sealed_pair
    assert verify_seal(mcap, seal_path, require_anchor=True) == 1


def test_require_anchor_fails_on_mismatched_commits(
    sealed_pair: tuple[Path, Path], tmp_path: Path
) -> None:
    """Anchor present but commits field is wrong; --require-anchor must return 1."""
    mcap, seal_path = sealed_pair
    manifest = json.loads(seal_path.read_bytes())
    manifest["anchor"] = {
        "type": "opentimestamps",
        "commitment_alg": "SHA-256",
        "commits": "00" * 32,  # deliberately wrong
        "ots_base64": base64.b64encode(b"fake").decode(),
        "status": "pending",
        "submitted_utc": "2026-01-01T00:00:00Z",
    }
    bad_seal = tmp_path / "bad_anchor.seal.json"
    bad_seal.write_bytes(canonical_json(manifest))
    assert verify_seal(mcap, bad_seal, require_anchor=True) == 1


def test_require_anchor_fails_on_pending_anchor(
    sealed_pair: tuple[Path, Path], tmp_path: Path
) -> None:
    """Valid commits but only a pending OTS proof; --require-anchor must return 1."""
    mcap, seal_path = sealed_pair
    manifest = json.loads(seal_path.read_bytes())

    # Compute the correct anchor commit digest (SHA-256 over manifest WITHOUT "anchor")
    payload_for_anchor = {k: v for k, v in manifest.items() if k != "anchor"}
    commits_hex = hashlib.sha256(canonical_json(payload_for_anchor)).hexdigest()

    manifest["anchor"] = {
        "type": "opentimestamps",
        "commitment_alg": "SHA-256",
        "commits": commits_hex,
        "ots_base64": base64.b64encode(b"mock-ots-bytes").decode(),
        "status": "pending",
        "submitted_utc": "2026-01-01T00:00:00Z",
    }
    valid_seal = tmp_path / "valid_anchor.seal.json"
    valid_seal.write_bytes(canonical_json(manifest))

    with patch("veriseal.anchor.verify_anchor", return_value=("pending", None)):
        result = verify_seal(mcap, valid_seal, require_anchor=True)
    assert result == 1


# ── canonical_json correctness ───────────────────────────────────────────────


def test_canonical_json_rejects_nan() -> None:
    with pytest.raises((ValueError, TypeError)):
        canonical_json({"x": float("nan")})


def test_canonical_json_rejects_inf() -> None:
    with pytest.raises((ValueError, TypeError)):
        canonical_json({"x": float("inf")})


# ── signing key type guards ──────────────────────────────────────────────────


def test_load_private_pem_rejects_non_ed25519(tmp_path: Path) -> None:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.rsa import generate_private_key

    from veriseal.signing import load_private_pem

    rsa_key = generate_private_key(65537, 2048)
    rsa_pem_path = tmp_path / "rsa.key.pem"
    rsa_pem_path.write_bytes(
        rsa_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    with pytest.raises(TypeError, match="Ed25519"):
        load_private_pem(rsa_pem_path)

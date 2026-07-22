"""Tests for `veriseal keygen` and the key-pinning workflow it enables."""

from __future__ import annotations

from pathlib import Path

from typer.testing import CliRunner

from veriseal.cli import app
from veriseal.signing import load_private_pem, public_pem

runner = CliRunner()


def test_keygen_writes_loadable_private_key(tmp_path: Path) -> None:
    key_path = tmp_path / "signer.key.pem"
    result = runner.invoke(app, ["keygen", "--out", str(key_path)])
    assert result.exit_code == 0
    assert key_path.exists()
    load_private_pem(key_path)  # must not raise


def test_keygen_pub_matches_private(tmp_path: Path) -> None:
    key_path = tmp_path / "signer.key.pem"
    pub_path = tmp_path / "signer.pub.pem"
    result = runner.invoke(app, ["keygen", "--out", str(key_path), "--pub", str(pub_path)])
    assert result.exit_code == 0
    expected_pub = public_pem(load_private_pem(key_path))
    assert pub_path.read_text(encoding="utf-8").strip() == expected_pub.strip()
    # the printed public key matches too
    assert expected_pub.strip() in result.stdout


def test_keygen_refuses_overwrite(tmp_path: Path) -> None:
    key_path = tmp_path / "signer.key.pem"
    runner.invoke(app, ["keygen", "--out", str(key_path)])
    original = key_path.read_bytes()
    result = runner.invoke(app, ["keygen", "--out", str(key_path)])
    assert result.exit_code == 1
    assert key_path.read_bytes() == original  # untouched


def test_keygen_force_overwrites(tmp_path: Path) -> None:
    key_path = tmp_path / "signer.key.pem"
    runner.invoke(app, ["keygen", "--out", str(key_path)])
    original = key_path.read_bytes()
    result = runner.invoke(app, ["keygen", "--out", str(key_path), "--force"])
    assert result.exit_code == 0
    assert key_path.read_bytes() != original  # a fresh key


def test_keygen_seal_verify_pinned(sample_mcap: Path, tmp_path: Path) -> None:
    """The keygen -> seal --key -> verify --pubkey pinning workflow succeeds."""
    key_path = tmp_path / "signer.key.pem"
    pub_path = tmp_path / "signer.pub.pem"
    r_keygen = runner.invoke(app, ["keygen", "--out", str(key_path), "--pub", str(pub_path)])
    assert r_keygen.exit_code == 0

    seal_path = tmp_path / "log.seal.json"
    seal_args = [
        "seal",
        str(sample_mcap),
        "--key",
        str(key_path),
        "--no-anchor",
        "--out",
        str(seal_path),
    ]
    assert runner.invoke(app, seal_args).exit_code == 0

    verify_args = ["verify", str(sample_mcap), str(seal_path), "--pubkey", str(pub_path)]
    assert runner.invoke(app, verify_args).exit_code == 0

    # A different (unpinned) key must fail the pin check.
    other = tmp_path / "other.pub.pem"
    runner.invoke(app, ["keygen", "--out", str(tmp_path / "other.key.pem"), "--pub", str(other)])
    r_bad = runner.invoke(app, ["verify", str(sample_mcap), str(seal_path), "--pubkey", str(other)])
    assert r_bad.exit_code == 1

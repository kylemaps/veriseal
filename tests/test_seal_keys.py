"""seal never creates or overwrites a signer key unless explicitly asked to."""

from __future__ import annotations

from pathlib import Path

import pytest
from typer.testing import CliRunner

from veriseal.cli import app
from veriseal.seal import seal

runner = CliRunner()


def test_seal_without_any_key_is_refused(sample_mcap: Path) -> None:
    with pytest.raises(ValueError, match="exactly one"):
        seal(sample_mcap, out_path=sample_mcap.with_suffix(".seal.json"), do_anchor=False)
    assert list(sample_mcap.parent.glob("*.pem")) == []


def test_seal_with_both_keys_is_refused(sample_mcap: Path, tmp_path: Path) -> None:
    runner.invoke(app, ["keygen", "--out", str(tmp_path / "a.key.pem")])
    with pytest.raises(ValueError, match="exactly one"):
        seal(
            sample_mcap,
            key_path=tmp_path / "a.key.pem",
            new_key_path=tmp_path / "b.key.pem",
            do_anchor=False,
        )


def test_new_key_never_overwrites(sample_mcap: Path, tmp_path: Path) -> None:
    existing = tmp_path / "signer.key.pem"
    existing.write_bytes(b"precious")
    seal_path = tmp_path / "out.seal.json"
    with pytest.raises(FileExistsError):
        seal(sample_mcap, new_key_path=existing, out_path=seal_path, do_anchor=False)
    assert existing.read_bytes() == b"precious"
    assert not seal_path.exists()


def test_cli_seal_without_key_exits_2_and_writes_nothing(sample_mcap: Path) -> None:
    before = sorted(p.name for p in sample_mcap.parent.iterdir())
    result = runner.invoke(app, ["seal", str(sample_mcap), "--no-anchor"])
    assert result.exit_code == 2
    assert "--key" in result.output and "--new-key" in result.output
    assert sorted(p.name for p in sample_mcap.parent.iterdir()) == before


def test_cli_seal_with_both_keys_exits_2(sample_mcap: Path, tmp_path: Path) -> None:
    key = tmp_path / "a.key.pem"
    runner.invoke(app, ["keygen", "--out", str(key)])
    args = ["seal", str(sample_mcap), "--key", str(key), "--new-key", str(tmp_path / "b.key.pem")]
    assert runner.invoke(app, [*args, "--no-anchor"]).exit_code == 2


def test_cli_new_key_refuses_existing_file(sample_mcap: Path, tmp_path: Path) -> None:
    existing = tmp_path / "signer.key.pem"
    existing.write_bytes(b"precious")
    args = ["seal", str(sample_mcap), "--new-key", str(existing), "--no-anchor"]
    result = runner.invoke(app, args)
    assert result.exit_code == 1
    assert "Refusing to overwrite" in " ".join(result.output.split())
    assert existing.read_bytes() == b"precious"


def test_cli_new_key_seals_and_prints_public_key(sample_mcap: Path, tmp_path: Path) -> None:
    key = tmp_path / "signer.key.pem"
    seal_path = tmp_path / "out.seal.json"
    args = ["seal", str(sample_mcap), "--new-key", str(key), "--no-anchor", "--out", str(seal_path)]
    result = runner.invoke(app, args)
    assert result.exit_code == 0
    assert key.exists() and seal_path.exists()
    assert "BEGIN PUBLIC KEY" in result.output

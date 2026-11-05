"""Signer keys: never created or overwritten implicitly, owner-only, optionally encrypted."""

from __future__ import annotations

import os
import stat
from pathlib import Path

import pytest
from typer.testing import CliRunner

from veriseal.cli import app
from veriseal.seal import seal
from veriseal.signing import KeyPassphraseError, generate_key, load_private_pem, save_private_pem

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


# key files: owner-only, never overwritten, optional passphrase

posix_only = pytest.mark.skipif(os.name != "posix", reason="file modes are POSIX-only")


def _mode(path: Path) -> int:
    return stat.S_IMODE(path.stat().st_mode)


@posix_only
def test_keygen_key_is_owner_only(tmp_path: Path) -> None:
    key = tmp_path / "signer.key.pem"
    assert runner.invoke(app, ["keygen", "--out", str(key)]).exit_code == 0
    assert _mode(key) == 0o600


@posix_only
def test_new_key_from_seal_is_owner_only(sample_mcap: Path, tmp_path: Path) -> None:
    key = tmp_path / "new.key.pem"
    seal(sample_mcap, new_key_path=key, out_path=tmp_path / "s.seal.json", do_anchor=False)
    assert _mode(key) == 0o600


def test_save_private_pem_never_replaces_a_file(tmp_path: Path) -> None:
    existing = tmp_path / "signer.key.pem"
    existing.write_bytes(b"precious")
    with pytest.raises(FileExistsError):
        save_private_pem(generate_key(), existing)
    assert existing.read_bytes() == b"precious"


def test_keygen_with_passphrase_writes_an_encrypted_key(tmp_path: Path) -> None:
    key = tmp_path / "signer.key.pem"
    result = runner.invoke(
        app,
        ["keygen", "--out", str(key), "--key-passphrase-env", "SIGNER_PASS"],
        env={"SIGNER_PASS": "correct horse"},
    )
    assert result.exit_code == 0
    assert b"ENCRYPTED PRIVATE KEY" in key.read_bytes()
    assert "encrypted, owner-only" in " ".join(result.stdout.split())
    with pytest.raises(KeyPassphraseError, match="is encrypted"):
        load_private_pem(key)
    load_private_pem(key, b"correct horse")  # must not raise


def _encrypted_key(tmp_path: Path) -> Path:
    key = tmp_path / "signer.key.pem"
    save_private_pem(generate_key(), key, b"correct horse")
    return key


def test_seal_with_an_encrypted_key_and_its_passphrase(sample_mcap: Path, tmp_path: Path) -> None:
    key = _encrypted_key(tmp_path)
    args = ["seal", str(sample_mcap), "--key", str(key), "--no-anchor"]
    args += ["--key-passphrase-env", "SIGNER_PASS", "--out", str(tmp_path / "s.seal.json")]
    result = runner.invoke(app, args, env={"SIGNER_PASS": "correct horse"})
    assert result.exit_code == 0, result.output
    assert (tmp_path / "s.seal.json").exists()


@pytest.mark.parametrize(
    ("extra", "env", "message"),
    [
        ([], {}, "is encrypted; give its passphrase (use --key-passphrase-env VAR)"),
        (["--key-passphrase-env", "SIGNER_PASS"], {"SIGNER_PASS": "wrong"}, "wrong passphrase"),
        (["--key-passphrase-env", "NOT_SET_ANYWHERE"], {}, "NOT_SET_ANYWHERE is not set"),
    ],
)
def test_seal_refuses_without_the_right_passphrase(
    sample_mcap: Path, tmp_path: Path, extra: list[str], env: dict[str, str], message: str
) -> None:
    key = _encrypted_key(tmp_path)
    out = tmp_path / "s.seal.json"
    args = ["seal", str(sample_mcap), "--key", str(key), "--no-anchor", "--out", str(out), *extra]
    result = runner.invoke(app, args, env=env)
    assert result.exit_code == 2
    assert message in " ".join(result.stdout.split())
    assert not out.exists()


def test_seal_new_key_with_passphrase_is_encrypted(sample_mcap: Path, tmp_path: Path) -> None:
    key = tmp_path / "new.key.pem"
    seal(
        sample_mcap,
        new_key_path=key,
        out_path=tmp_path / "s.seal.json",
        do_anchor=False,
        passphrase=b"correct horse",
    )
    assert b"ENCRYPTED PRIVATE KEY" in key.read_bytes()

"""Hermetic tests for veriseal pack (no network — --no-anchor throughout)."""

from __future__ import annotations

import json
import zipfile
from pathlib import Path

import pytest
from mcap.writer import Writer

from veriseal.pack import build_pack
from veriseal.seal import seal

# ── helpers ──────────────────────────────────────────────────────────────────


def _write_mcap(path: Path, messages: list[tuple[str, int, bytes]]) -> Path:
    topics = sorted({topic for topic, _, _ in messages})
    with open(path, "wb") as f:
        writer = Writer(f)
        writer.start()
        schema_id = writer.register_schema(name="raw", encoding="", data=b"")
        channel_ids = {
            topic: writer.register_channel(topic=topic, message_encoding="", schema_id=schema_id)
            for topic in topics
        }
        for topic, log_time, data in messages:
            writer.add_message(
                channel_id=channel_ids[topic], log_time=log_time, data=data, publish_time=log_time
            )
        writer.finish()
    return path


_MESSAGES: list[tuple[str, int, bytes]] = [
    ("/pose", 1_000_000, b"\x01"),
    ("/status", 2_000_000, b"\xaa"),
    ("/pose", 3_000_000, b"\x02"),
    ("/status", 4_000_000, b"\xbb"),
    ("/pose", 5_000_000, b"\x03"),
]


@pytest.fixture
def sealed_pair(tmp_path: Path) -> tuple[Path, Path]:
    mcap = _write_mcap(tmp_path / "orig.mcap", _MESSAGES)
    seal_path = tmp_path / "orig.seal.json"
    seal(mcap, key_path=None, out_path=seal_path, do_anchor=False)
    return mcap, seal_path


# ── contents ─────────────────────────────────────────────────────────────────


def test_pack_ok_on_intact_log(sealed_pair: tuple[Path, Path], tmp_path: Path) -> None:
    mcap, seal_path = sealed_pair
    result = build_pack(mcap, seal_path, tmp_path / "pack")
    assert result.ok is True


def test_pack_writes_expected_files(sealed_pair: tuple[Path, Path], tmp_path: Path) -> None:
    mcap, seal_path = sealed_pair
    out_dir = tmp_path / "pack"
    build_pack(mcap, seal_path, out_dir)
    assert (out_dir / "manifest.seal.json").exists()
    assert (out_dir / "report.txt").exists()
    assert (out_dir / "cover-sheet.txt").exists()
    assert (out_dir / "README.txt").exists()
    # sealed without --anchor: no OTS proof to bundle
    assert not (out_dir / "anchor.ots").exists()


def test_pack_bundles_web_verifier(sealed_pair: tuple[Path, Path], tmp_path: Path) -> None:
    mcap, seal_path = sealed_pair
    out_dir = tmp_path / "pack"
    build_pack(mcap, seal_path, out_dir)
    bundled = out_dir / "verify.html"
    assert bundled.exists()
    original = Path(__file__).resolve().parent.parent / "web" / "verify.html"
    assert bundled.read_bytes() == original.read_bytes()


def test_web_verifier_bundled_into_wheel() -> None:
    """The offline verifier must be force-included into the wheel, or a pip-installed
    `veriseal pack` would silently omit it while the cover sheet claims it is present.

    Guards the [tool.hatch.build.targets.wheel.force-include] mapping in pyproject.toml.
    """
    import tomllib

    pyproject = Path(__file__).resolve().parent.parent / "pyproject.toml"
    config = tomllib.loads(pyproject.read_text(encoding="utf-8"))
    force_include = config["tool"]["hatch"]["build"]["targets"]["wheel"]["force-include"]
    # web/verify.html must be mapped into the veriseal package tree
    assert "web/verify.html" in force_include
    assert force_include["web/verify.html"].startswith("veriseal/")


def test_pack_manifest_is_verbatim(sealed_pair: tuple[Path, Path], tmp_path: Path) -> None:
    """The bundled manifest must be byte-identical (as canonical JSON) to the input."""
    mcap, seal_path = sealed_pair
    out_dir = tmp_path / "pack"
    build_pack(mcap, seal_path, out_dir)
    original = json.loads(seal_path.read_bytes())
    bundled = json.loads((out_dir / "manifest.seal.json").read_bytes())
    assert original == bundled


# ── report content matches the verification result ───────────────────────────


def test_report_reflects_signature_and_root(sealed_pair: tuple[Path, Path], tmp_path: Path) -> None:
    mcap, seal_path = sealed_pair
    out_dir = tmp_path / "pack"
    result = build_pack(mcap, seal_path, out_dir)
    report = (out_dir / "report.txt").read_text(encoding="utf-8")
    manifest = json.loads(seal_path.read_bytes())

    assert "INTACT" in report
    assert "[PASS] Manifest signature" in report
    assert "[PASS] Merkle root" in report
    assert manifest["merkle"]["root"] in report
    assert result.result.sig_ok is True
    assert result.result.root_ok is True


def test_report_never_claims_confirmed_when_no_anchor(
    sealed_pair: tuple[Path, Path], tmp_path: Path
) -> None:
    mcap, seal_path = sealed_pair
    out_dir = tmp_path / "pack"
    build_pack(mcap, seal_path, out_dir)
    report = (out_dir / "report.txt").read_text(encoding="utf-8")
    assert "Timestamp anchor: NONE" in report
    assert "CONFIRMED" not in report
    assert "confirmed" not in report.lower()


def test_report_never_asserts_content_is_true(
    sealed_pair: tuple[Path, Path], tmp_path: Path
) -> None:
    """The cover sheet must state the self-forgery limit, not assert log truthfulness,
    and must not claim the bundle satisfies or complies with any regulation."""
    mcap, seal_path = sealed_pair
    out_dir = tmp_path / "pack"
    build_pack(mcap, seal_path, out_dir)
    cover = (out_dir / "cover-sheet.txt").read_text(encoding="utf-8").lower()
    assert "truthful record of what happened" in cover
    assert "not itself satisfy" in cover
    assert "not a compliance certificate" in cover
    assert "complies with" not in cover


def test_report_on_tampered_log_says_tampered(
    sealed_pair: tuple[Path, Path], tmp_path: Path
) -> None:
    _, seal_path = sealed_pair
    tampered_msgs = [
        ("/pose", 1_000_000, b"\x01"),
        ("/status", 2_000_000, b"\xaa"),
        ("/pose", 3_000_000, b"\xff"),  # payload changed
        ("/status", 4_000_000, b"\xbb"),
        ("/pose", 5_000_000, b"\x03"),
    ]
    tampered_mcap = _write_mcap(tmp_path / "tampered.mcap", tampered_msgs)
    out_dir = tmp_path / "pack"
    result = build_pack(tampered_mcap, seal_path, out_dir)
    assert result.ok is False
    report = (out_dir / "report.txt").read_text(encoding="utf-8")
    assert "TAMPERED" in report
    assert "MODIFIED" in report
    assert "/pose" in report


# ── determinism ──────────────────────────────────────────────────────────────


def test_pack_is_byte_deterministic_except_generated_line(
    sealed_pair: tuple[Path, Path], tmp_path: Path
) -> None:
    """Re-running pack on identical inputs must produce identical bytes for every
    file except the explicitly-labelled 'Report generated' line in report.txt,
    which is not part of the evidence."""
    mcap, seal_path = sealed_pair
    out_a = tmp_path / "pack_a"
    out_b = tmp_path / "pack_b"
    build_pack(mcap, seal_path, out_a)
    build_pack(mcap, seal_path, out_b)

    manifest_a = (out_a / "manifest.seal.json").read_bytes()
    manifest_b = (out_b / "manifest.seal.json").read_bytes()
    assert manifest_a == manifest_b
    assert (out_a / "cover-sheet.txt").read_bytes() == (out_b / "cover-sheet.txt").read_bytes()
    assert (out_a / "README.txt").read_bytes() == (out_b / "README.txt").read_bytes()
    assert (out_a / "verify.html").read_bytes() == (out_b / "verify.html").read_bytes()

    report_a = (out_a / "report.txt").read_text(encoding="utf-8").splitlines()
    report_b = (out_b / "report.txt").read_text(encoding="utf-8").splitlines()
    assert len(report_a) == len(report_b)
    diffs = [(i, a, b) for i, (a, b) in enumerate(zip(report_a, report_b, strict=True)) if a != b]
    assert len(diffs) <= 1
    if diffs:
        i, a, b = diffs[0]
        assert a.startswith("Report generated:")
        assert b.startswith("Report generated:")


def test_report_generated_line_excluded_from_signed_content(
    sealed_pair: tuple[Path, Path], tmp_path: Path
) -> None:
    """The report explicitly labels its generation time as outside the evidence,
    and that line must not appear anywhere in the signed manifest bytes."""
    mcap, seal_path = sealed_pair
    out_dir = tmp_path / "pack"
    build_pack(mcap, seal_path, out_dir)
    report = (out_dir / "report.txt").read_text(encoding="utf-8")
    assert "not part of the sealed evidence" in report
    manifest_bytes = (out_dir / "manifest.seal.json").read_bytes()
    assert b"Report generated" not in manifest_bytes


# ── zip output ───────────────────────────────────────────────────────────────


def test_pack_zip_creates_archive(sealed_pair: tuple[Path, Path], tmp_path: Path) -> None:
    mcap, seal_path = sealed_pair
    result = build_pack(mcap, seal_path, tmp_path / "bundle", as_zip=True)
    assert result.is_zip is True
    assert result.out == tmp_path / "bundle.zip"  # .zip suffix auto-appended
    assert result.out.is_file()
    assert not (tmp_path / "bundle").exists()  # no leftover directory


def test_pack_zip_contains_all_files(sealed_pair: tuple[Path, Path], tmp_path: Path) -> None:
    mcap, seal_path = sealed_pair
    result = build_pack(mcap, seal_path, tmp_path / "bundle.zip", as_zip=True)
    with zipfile.ZipFile(result.out) as zf:
        names = set(zf.namelist())
        assert {
            "manifest.seal.json",
            "report.txt",
            "cover-sheet.txt",
            "README.txt",
            "verify.html",
        } <= names
        # bundled manifest inside the zip is verbatim
        bundled = json.loads(zf.read("manifest.seal.json"))
    assert bundled == json.loads(seal_path.read_bytes())


def test_pack_zip_suffix_not_doubled(sealed_pair: tuple[Path, Path], tmp_path: Path) -> None:
    mcap, seal_path = sealed_pair
    result = build_pack(mcap, seal_path, tmp_path / "already.zip", as_zip=True)
    assert result.out == tmp_path / "already.zip"
    assert result.out.is_file()


def test_cli_pack_zip_flag(sealed_pair: tuple[Path, Path], tmp_path: Path) -> None:
    mcap, seal_path = sealed_pair
    from typer.testing import CliRunner

    from veriseal.cli import app

    out = tmp_path / "bundle"
    args = ["pack", str(mcap), str(seal_path), "--out", str(out), "--zip"]
    result = CliRunner().invoke(app, args)
    assert result.exit_code == 0
    assert (tmp_path / "bundle.zip").is_file()


# ── exit code plumbing (CLI) ───────────────────────────────────────────────


def test_cli_pack_exit_code_ok(sealed_pair: tuple[Path, Path], tmp_path: Path) -> None:
    mcap, seal_path = sealed_pair
    from typer.testing import CliRunner

    from veriseal.cli import app

    runner = CliRunner()
    args = ["pack", str(mcap), str(seal_path), "--out", str(tmp_path / "pack")]
    result = runner.invoke(app, args)
    assert result.exit_code == 0


def test_cli_pack_exit_code_failure(sealed_pair: tuple[Path, Path], tmp_path: Path) -> None:
    _, seal_path = sealed_pair
    tampered_msgs = [
        ("/pose", 1_000_000, b"\x01"),
        ("/status", 2_000_000, b"\xaa"),
        ("/pose", 3_000_000, b"\xff"),
        ("/status", 4_000_000, b"\xbb"),
        ("/pose", 5_000_000, b"\x03"),
    ]
    tampered_mcap = _write_mcap(tmp_path / "tampered.mcap", tampered_msgs)
    from typer.testing import CliRunner

    from veriseal.cli import app

    runner = CliRunner()
    result = runner.invoke(
        app, ["pack", str(tampered_mcap), str(seal_path), "--out", str(tmp_path / "pack")]
    )
    assert result.exit_code == 1

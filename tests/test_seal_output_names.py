"""Output-name derivation preserves dotted stems (no collisions)."""

from __future__ import annotations

from pathlib import Path

from mcap.writer import Writer

from veriseal.seal import _derive_output, seal


def test_derive_output_simple() -> None:
    p = Path("/logs/drive.mcap")
    assert _derive_output(p, ".seal.json") == Path("/logs/drive.seal.json")
    assert _derive_output(p, ".key.pem") == Path("/logs/drive.key.pem")


def test_derive_output_dotted_stem_preserved() -> None:
    # The bug: with_suffix() dropped the middle segment (-> data.seal.json).
    p = Path("/logs/data.2026.mcap")
    assert _derive_output(p, ".seal.json") == Path("/logs/data.2026.seal.json")


def test_derive_output_distinct_dotted_stems_do_not_collide() -> None:
    a = _derive_output(Path("data.2026.mcap"), ".seal.json")
    b = _derive_output(Path("data.2025.mcap"), ".seal.json")
    assert a != b


def test_derive_output_bag_extension() -> None:
    assert _derive_output(Path("drive.bag"), ".seal.json") == Path("drive.seal.json")


def test_derive_output_no_known_extension() -> None:
    # Nothing to strip: append rather than mangle.
    assert _derive_output(Path("logfile"), ".seal.json") == Path("logfile.seal.json")


def test_seal_writes_default_names_with_dotted_stem(tmp_path: Path) -> None:
    mcap = tmp_path / "data.2026.mcap"
    with open(mcap, "wb") as f:
        w = Writer(f)
        w.start()
        sid = w.register_schema(name="raw", encoding="", data=b"")
        cid = w.register_channel(topic="/pose", message_encoding="", schema_id=sid)
        w.add_message(channel_id=cid, log_time=1_000_000, data=b"\x01", publish_time=1_000_000)
        w.finish()

    seal(mcap, key_path=None, out_path=None, do_anchor=False)
    assert (tmp_path / "data.2026.seal.json").exists()
    assert (tmp_path / "data.2026.key.pem").exists()

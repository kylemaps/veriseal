"""The streaming-seal vectors: the reference verifier and the independent one must agree."""

from __future__ import annotations

from pathlib import Path

import pytest

from tests.test_bench_measure import REPO, _load
from veriseal.tail import main as reference

STREAM = REPO / "conformance" / "stream"
checker = _load("check_stream", REPO / "conformance" / "check_stream.py")
maker = _load("make_stream_vectors", REPO / "conformance" / "make_stream_vectors.py")

OK, FAILED, LATE = 0, 1, 2
# log, seal folder, extra options, expected verdict
CASES = [
    ("log.mcap", "sealed", [], OK),
    ("log.reordered.mcap", "sealed", [], OK),
    ("log.tampered.mcap", "sealed", [], FAILED),
    ("log.missing.mcap", "sealed", [], FAILED),
    ("late.mcap", "late-sealed", [], LATE),
    ("late.mcap", "late-sealed", ["--max-lag-ms", "3000"], OK),
    ("late.mcap", "late-sealed", ["--max-lag-ms", "60"], LATE),
    ("late.mcap", "sealed", [], OK),  # the same messages in another order
    ("log.tampered.mcap", "late-sealed", [], FAILED),
]


@pytest.mark.parametrize(("log", "folder", "options", "expected"), CASES)
def test_both_verifiers_give_the_expected_verdict(log, folder, options, expected, capsys):
    paths = [str(STREAM / log), str(STREAM / folder)]
    assert checker.main([*paths, *options]) == expected
    assert reference(["verify", paths[0], "--out-dir", paths[1], *options]) == expected


def test_the_seal_files_are_reproducible(tmp_path: Path):
    maker.main(tmp_path)
    for folder in ("sealed", "late-sealed"):
        for name in ("start.json", "keys.json", "heads.jsonl", "leaves.bin"):
            made, kept = tmp_path / folder / name, STREAM / folder / name
            assert made.read_bytes().replace(b"\r\n", b"\n") == kept.read_bytes().replace(
                b"\r\n", b"\n"
            ), f"{folder}/{name} differs: run conformance/make_stream_vectors.py"


@pytest.mark.parametrize(
    ("file", "change", "reason"),
    [
        ("start.json", (b'"segment":0', b'"segment":1'), "bad start record signature"),
        ("keys.json", (b'"public_keys": [\n  "', b'"public_keys": [\n  "00'), None),
        ("heads.jsonl", (b'"tree_size":10', b'"tree_size":11'), "head 0 has a bad signature"),
    ],
)
def test_the_independent_checker_rejects_a_changed_seal(tmp_path: Path, file, change, reason):
    for name in ("start.json", "keys.json", "heads.jsonl"):
        (tmp_path / name).write_bytes((STREAM / "sealed" / name).read_bytes())
    data = (tmp_path / file).read_bytes().replace(b"\r\n", b"\n")
    assert change[0] in data
    (tmp_path / file).write_bytes(data.replace(change[0], change[1], 1))
    verdict, why = checker.check(STREAM / "log.mcap", tmp_path)
    assert verdict == FAILED
    assert reason is None or why == reason
    assert reference(["verify", str(STREAM / "log.mcap"), "--out-dir", str(tmp_path)]) == FAILED

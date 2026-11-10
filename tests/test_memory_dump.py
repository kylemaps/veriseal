"""bench/memory_dump.py: the scan must find the live seed, then counts the erased ones left."""

from __future__ import annotations

import sys

import pytest

from tests.test_bench_measure import REPO, _load

dump = _load("memory_dump", REPO / "bench" / "memory_dump.py")


@pytest.mark.skipif(
    not sys.platform.startswith(("linux", "win32")),
    reason="reads another process's memory only on Linux and Windows",
)
@pytest.mark.parametrize("mode", ["bare", "sealer"])
def test_a_scan_finds_the_live_seed_and_counts_the_erased_ones(mode):
    row = dump.run(mode)
    assert row["mode"] == mode
    assert 0 <= row["old_seeds_found"] <= dump.EPOCHS
    assert 0 <= row["old_private_keys_found"] <= dump.EPOCHS
    assert row["scanned_mb"] > 1

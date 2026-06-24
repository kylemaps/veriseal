"""MCAP file I/O helpers."""

from __future__ import annotations

import hashlib
from collections.abc import Iterator
from pathlib import Path

from mcap.reader import make_reader


def iter_messages(path: Path) -> Iterator[tuple[str, int, bytes]]:
    """Yield (topic, log_time_ns, payload_bytes) for every message in *path*."""
    with open(path, "rb") as f:
        reader = make_reader(f)
        for _schema, channel, message in reader.iter_messages():
            yield channel.topic, message.log_time, message.data


def file_digest(path: Path) -> tuple[str, int]:
    """Return (sha256_hex, size_bytes) for *path* using streaming reads."""
    h = hashlib.sha256()
    size = 0
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
            size += len(chunk)
    return h.hexdigest(), size

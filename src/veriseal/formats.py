"""Format-agnostic message extraction for sealing and verifying.

veriseal hashes ``(topic, log_time_ns, payload_bytes)`` triples into Merkle
leaves; that shape is not MCAP-specific. This module maps each supported
container format onto those triples, so the same seal/verify pipeline covers
more than MCAP without changing the manifest format or the crypto.

Supported today:
  - MCAP        (``.mcap``) — native.
  - ROS 1 bag   (``.bag``)  — via the optional ``rosbags`` dependency
                              (``pip install veriseal[ros1]``); pure Python, no
                              ROS installation required.

Both seal and verify read the same file through the same reader, so the
recomputed leaves match byte-for-byte regardless of format.
"""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

from veriseal.mcap_io import iter_messages as _iter_mcap

FORMAT_MCAP = "mcap"
FORMAT_ROSBAG1 = "rosbag1"


def detect_format(path: Path) -> str:
    """Return the veriseal format id for *path*, by extension.

    Raises ValueError for unrecognized extensions.
    """
    suffix = path.suffix.lower()
    if suffix == ".mcap":
        return FORMAT_MCAP
    if suffix == ".bag":
        return FORMAT_ROSBAG1
    raise ValueError(
        f"Unrecognized log format for {path.name!r} (expected .mcap or .bag). "
        "Convert to MCAP first (see docs/ros1.md), or open an issue for the format you need."
    )


def _iter_rosbag1(path: Path) -> Iterator[tuple[str, int, bytes]]:
    try:
        from rosbags.rosbag1 import Reader
    except ModuleNotFoundError as exc:  # pragma: no cover - exercised via message only
        raise ModuleNotFoundError(
            "Reading ROS 1 .bag files needs the 'rosbags' package. "
            "Install it with:  pip install veriseal[ros1]"
        ) from exc

    with Reader(str(path)) as reader:
        for connection, timestamp, rawdata in reader.messages():
            yield connection.topic, int(timestamp), bytes(rawdata)


def iter_messages(path: Path) -> Iterator[tuple[str, int, bytes]]:
    """Yield ``(topic, log_time_ns, payload_bytes)`` for every message in *path*.

    Dispatches on the file format detected from the extension.
    """
    fmt = detect_format(path)
    if fmt == FORMAT_MCAP:
        yield from _iter_mcap(path)
    else:  # FORMAT_ROSBAG1
        yield from _iter_rosbag1(path)

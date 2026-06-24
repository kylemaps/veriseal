"""Hermetic tests for veriseal inspect."""

from __future__ import annotations

from pathlib import Path

import pytest
from mcap.reader import make_reader

from veriseal.inspect import inspect_mcap, parse_time

# ── parse_time ────────────────────────────────────────────────────────────────


def test_parse_time_integer_ns():
    assert parse_time("1000000") == 1_000_000
    assert parse_time("0") == 0


def test_parse_time_iso8601_utc():
    ns = parse_time("2026-06-24T12:00:00Z")
    assert ns > 0
    # Reconstruct and compare year/month/day to verify round-trip.
    from datetime import UTC, datetime, timedelta

    epoch = datetime(1970, 1, 1, tzinfo=UTC)
    dt = epoch + timedelta(seconds=ns // 1_000_000_000, microseconds=(ns % 1_000_000_000) // 1000)
    assert (dt.year, dt.month, dt.day) == (2026, 6, 24)
    assert (dt.hour, dt.minute, dt.second) == (12, 0, 0)


def test_parse_time_iso8601_offset():
    """Explicit +00:00 offset is accepted."""
    ns1 = parse_time("2026-06-24T12:00:00Z")
    ns2 = parse_time("2026-06-24T12:00:00+00:00")
    assert ns1 == ns2


def test_parse_time_iso8601_microseconds():
    """1 µs = 1000 ns above the base second."""
    base = parse_time("2026-06-24T12:00:00Z")
    with_us = parse_time("2026-06-24T12:00:00.000001Z")
    assert with_us - base == 1_000


def test_parse_time_invalid():
    with pytest.raises(ValueError):
        parse_time("not-a-time")


def test_parse_time_no_timezone():
    with pytest.raises(ValueError, match="timezone"):
        parse_time("2026-06-24T12:00:00")


# ── inspect_mcap — windowing ──────────────────────────────────────────────────


def test_inspect_window_returns_0(sample_mcap: Path, tmp_path: Path) -> None:
    out = tmp_path / "out.incident.mcap"
    assert inspect_mcap(sample_mcap, 2_000_000, 4_000_000, None, out) == 0


def test_inspect_window_count(sample_mcap: Path, tmp_path: Path) -> None:
    """Window [2M, 4M] is inclusive → t=2M, 3M, 4M → 3 messages."""
    out = tmp_path / "window3.incident.mcap"
    inspect_mcap(sample_mcap, 2_000_000, 4_000_000, None, out)
    with open(out, "rb") as f:
        msgs = list(make_reader(f).iter_messages())
    assert len(msgs) == 3


def test_inspect_window_correct_messages(sample_mcap: Path, tmp_path: Path) -> None:
    """The three messages in [2M, 4M] should have the correct log_times and topics."""
    out = tmp_path / "window3b.incident.mcap"
    inspect_mcap(sample_mcap, 2_000_000, 4_000_000, None, out)
    with open(out, "rb") as f:
        msgs = list(make_reader(f).iter_messages())
    log_times = sorted(msg.log_time for _, _, msg in msgs)
    topics = {msg.log_time: ch.topic for _, ch, msg in msgs}
    assert log_times == [2_000_000, 3_000_000, 4_000_000]
    assert topics[2_000_000] == "/status"
    assert topics[3_000_000] == "/pose"
    assert topics[4_000_000] == "/status"


def test_inspect_from_after_to(sample_mcap: Path, tmp_path: Path) -> None:
    """from > to must return 2 (usage error)."""
    assert inspect_mcap(sample_mcap, 5_000_000, 1_000_000, None, tmp_path / "x.mcap") == 2


def test_inspect_empty_window(sample_mcap: Path, tmp_path: Path) -> None:
    """A window containing no messages writes a valid 0-message MCAP."""
    out = tmp_path / "empty.incident.mcap"
    assert inspect_mcap(sample_mcap, 9_000_000, 10_000_000, None, out) == 0
    with open(out, "rb") as f:
        msgs = list(make_reader(f).iter_messages())
    assert len(msgs) == 0


# ── inspect_mcap — topic filter ───────────────────────────────────────────────


def test_inspect_topic_filter_count(sample_mcap: Path, tmp_path: Path) -> None:
    """--topic=/pose over full range → 3 messages (t=1M, 3M, 5M)."""
    out = tmp_path / "pose.incident.mcap"
    inspect_mcap(sample_mcap, 0, 10_000_000, "/pose", out)
    with open(out, "rb") as f:
        msgs = list(make_reader(f).iter_messages())
    assert len(msgs) == 3


def test_inspect_topic_filter_topics(sample_mcap: Path, tmp_path: Path) -> None:
    out = tmp_path / "pose2.incident.mcap"
    inspect_mcap(sample_mcap, 0, 10_000_000, "/pose", out)
    with open(out, "rb") as f:
        msgs = list(make_reader(f).iter_messages())
    assert all(ch.topic == "/pose" for _, ch, _ in msgs)


def test_inspect_topic_and_window(sample_mcap: Path, tmp_path: Path) -> None:
    """Combined: --topic=/status AND window [2M, 3M] → only t=2M."""
    out = tmp_path / "status_narrow.incident.mcap"
    inspect_mcap(sample_mcap, 2_000_000, 3_000_000, "/status", out)
    with open(out, "rb") as f:
        msgs = list(make_reader(f).iter_messages())
    assert len(msgs) == 1
    _, ch, msg = msgs[0]
    assert ch.topic == "/status"
    assert msg.log_time == 2_000_000


# ── incident.mcap round-trip validity ────────────────────────────────────────


def test_incident_mcap_full_roundtrip(sample_mcap: Path, tmp_path: Path) -> None:
    """Full window: incident.mcap re-opens and contains all 5 messages with schemas."""
    out = tmp_path / "full.incident.mcap"
    inspect_mcap(sample_mcap, 1_000_000, 5_000_000, None, out)
    with open(out, "rb") as f:
        msgs = list(make_reader(f).iter_messages())
    assert len(msgs) == 5
    log_times = [msg.log_time for _, _, msg in msgs]
    assert sorted(log_times) == log_times  # chronological
    assert set(log_times) == {1_000_000, 2_000_000, 3_000_000, 4_000_000, 5_000_000}


def test_incident_mcap_schema_resolves(sample_mcap: Path, tmp_path: Path) -> None:
    """Every message in the incident slice must resolve its schema (not None)."""
    out = tmp_path / "schema_check.incident.mcap"
    inspect_mcap(sample_mcap, 1_000_000, 5_000_000, None, out)
    with open(out, "rb") as f:
        msgs = list(make_reader(f).iter_messages())
    assert all(schema is not None for schema, _, _ in msgs)


def test_incident_mcap_payload_preserved(sample_mcap: Path, tmp_path: Path) -> None:
    """Raw payload bytes must be identical after the roundtrip."""
    out = tmp_path / "payload.incident.mcap"
    inspect_mcap(sample_mcap, 1_000_000, 5_000_000, None, out)
    with open(out, "rb") as f:
        msgs = list(make_reader(f).iter_messages())
    payloads_by_time = {msg.log_time: msg.data for _, _, msg in msgs}
    assert payloads_by_time[1_000_000] == b"\x01"
    assert payloads_by_time[2_000_000] == b"\xaa"
    assert payloads_by_time[3_000_000] == b"\x02"
    assert payloads_by_time[4_000_000] == b"\xbb"
    assert payloads_by_time[5_000_000] == b"\x03"


def test_incident_mcap_default_output_path(sample_mcap: Path) -> None:
    """Default output path is <stem>.incident.mcap next to the source."""
    result = inspect_mcap(sample_mcap, 1_000_000, 5_000_000, None, None)
    assert result == 0
    expected = sample_mcap.with_name(sample_mcap.stem + ".incident.mcap")
    assert expected.exists()

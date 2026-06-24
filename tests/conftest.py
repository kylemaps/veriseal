"""Shared pytest fixtures."""

from __future__ import annotations

from pathlib import Path

import pytest
from mcap.writer import Writer


@pytest.fixture
def sample_mcap(tmp_path: Path) -> Path:
    """
    Write a deterministic MCAP with 5 messages across 2 topics.

    /pose   at t=1_000_000, 3_000_000, 5_000_000  payloads: 0x01, 0x02, 0x03
    /status at t=2_000_000, 4_000_000              payloads: 0xaa, 0xbb
    """
    mcap_path = tmp_path / "sample.mcap"
    with open(mcap_path, "wb") as f:
        writer = Writer(f)
        writer.start()
        schema_id = writer.register_schema(name="raw", encoding="", data=b"")
        ch_pose = writer.register_channel(
            topic="/pose", message_encoding="", schema_id=schema_id
        )
        ch_status = writer.register_channel(
            topic="/status", message_encoding="", schema_id=schema_id
        )
        writer.add_message(
            channel_id=ch_pose, log_time=1_000_000, data=b"\x01", publish_time=1_000_000
        )
        writer.add_message(
            channel_id=ch_status, log_time=2_000_000, data=b"\xaa", publish_time=2_000_000
        )
        writer.add_message(
            channel_id=ch_pose, log_time=3_000_000, data=b"\x02", publish_time=3_000_000
        )
        writer.add_message(
            channel_id=ch_status, log_time=4_000_000, data=b"\xbb", publish_time=4_000_000
        )
        writer.add_message(
            channel_id=ch_pose, log_time=5_000_000, data=b"\x03", publish_time=5_000_000
        )
        writer.finish()
    return mcap_path

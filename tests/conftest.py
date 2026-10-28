"""Shared pytest fixtures."""

from __future__ import annotations

import ipaddress
import socket
from pathlib import Path

import pytest
from mcap.writer import Writer

_LOCAL_HOSTNAMES = {"localhost", "localhost.localdomain"}


def _is_local(host: object) -> bool:
    if host is None:
        return True
    if isinstance(host, bytes):
        host = host.decode("ascii", "replace")
    if not isinstance(host, str):
        return False
    if host.lower() in _LOCAL_HOSTNAMES:
        return True
    try:
        return ipaddress.ip_address(host.split("%", 1)[0]).is_loopback
    except ValueError:
        return False


@pytest.fixture(autouse=True)
def _no_network(monkeypatch: pytest.MonkeyPatch):
    """Fail any test that reaches past loopback, even if the code under test swallows the error."""
    attempts: list[str] = []
    real_getaddrinfo = socket.getaddrinfo
    real_connect = socket.socket.connect
    real_connect_ex = socket.socket.connect_ex

    def _blocked(what: str) -> OSError:
        attempts.append(what)
        return OSError(f"network access is blocked in tests: {what}")

    def getaddrinfo(host, *args, **kwargs):
        if not _is_local(host):
            raise _blocked(f"DNS lookup of {host!r}")
        return real_getaddrinfo(host, *args, **kwargs)

    def connect(self, address):
        if isinstance(address, tuple) and not _is_local(address[0]):
            raise _blocked(f"connect to {address!r}")
        return real_connect(self, address)

    def connect_ex(self, address):
        if isinstance(address, tuple) and not _is_local(address[0]):
            raise _blocked(f"connect to {address!r}")
        return real_connect_ex(self, address)

    monkeypatch.setattr(socket, "getaddrinfo", getaddrinfo)
    monkeypatch.setattr(socket.socket, "connect", connect)
    monkeypatch.setattr(socket.socket, "connect_ex", connect_ex)
    yield attempts
    if attempts:
        pytest.fail("test tried to use the network: " + "; ".join(attempts), pytrace=False)


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
        ch_pose = writer.register_channel(topic="/pose", message_encoding="", schema_id=schema_id)
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

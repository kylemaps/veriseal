"""The conftest network guard: tests must never reach past loopback."""

from __future__ import annotations

import socket

import pytest


def test_guard_records_dns_lookup_even_when_error_is_swallowed(_no_network: list[str]) -> None:
    try:
        socket.create_connection(("example.com", 443), timeout=1)
    except OSError:
        pass
    assert _no_network == ["DNS lookup of 'example.com'"]
    _no_network.clear()  # otherwise the recorded attempt fails this test at teardown


def test_guard_blocks_direct_ip_connect(_no_network: list[str]) -> None:
    sock = socket.socket()
    try:
        with pytest.raises(OSError, match="blocked in tests"):
            sock.connect(("192.0.2.1", 443))
    finally:
        sock.close()
    assert _no_network == ["connect to ('192.0.2.1', 443)"]
    _no_network.clear()


def test_guard_allows_loopback(_no_network: list[str]) -> None:
    server = socket.socket()
    server.bind(("127.0.0.1", 0))
    server.listen(1)
    try:
        port = server.getsockname()[1]
        socket.create_connection(("127.0.0.1", port), timeout=1).close()
    finally:
        server.close()
    assert _no_network == []

"""The tailing sealer: reading an MCAP file while it grows, and sealing it on the clock."""

from __future__ import annotations

import io
import random
import subprocess
import sys
import time
from pathlib import Path

import pytest
from mcap.writer import CompressionType, Writer

from veriseal.mcap_io import iter_messages
from veriseal.signing import generate_key, public_pem
from veriseal.stream import (
    Segment,
    StreamSealer,
    begin_segment,
    check_heads,
    check_log,
    epoch_checker,
    start_hash,
    verify_task,
)
from veriseal.tail import McapTail, check_sealed, main, seal_growing_log

SECOND = 1_000_000_000
MS = 1_000_000
START = 1_700_000_000 * SECOND
TASK = "task-42"
BLOCK = "ab" * 32


def _messages(seconds: int = 6, rate_hz: int = 20, start_ns: int = START):
    step = SECOND // rate_hz
    return [
        (f"/t{i % 3}", start_ns + i * step, i.to_bytes(4, "big") * 50)
        for i in range(seconds * rate_hz)
    ]


def _mcap_bytes(messages, **options) -> bytes:
    out = io.BytesIO()
    writer = Writer(out, **options)
    writer.start()
    schema = writer.register_schema(name="raw", encoding="", data=b"")
    channels: dict[str, int] = {}
    for topic, log_time, payload in messages:
        if topic not in channels:
            channels[topic] = writer.register_channel(topic, "", schema)
        writer.add_message(channels[topic], log_time=log_time, data=payload, publish_time=log_time)
    writer.finish()
    return out.getvalue()


LAYOUTS = {
    "zstd chunks": {"chunk_size": 4096, "compression": CompressionType.ZSTD},
    "lz4 chunks": {"chunk_size": 4096, "compression": CompressionType.LZ4},
    "plain chunks": {"chunk_size": 4096, "compression": CompressionType.NONE},
    "no chunks": {"use_chunking": False},
}


def _read_all(path: Path):
    tail = McapTail(path)
    try:
        return tail.poll(), tail.done
    finally:
        tail.close()


# Reading a file that is still being written.


@pytest.mark.parametrize("layout", LAYOUTS)
def test_reads_what_the_standard_reader_reads(tmp_path, layout):
    path = tmp_path / "log.mcap"
    path.write_bytes(_mcap_bytes(_messages(), **LAYOUTS[layout]))
    read, done = _read_all(path)
    assert read == list(iter_messages(path)) == _messages()
    assert done


@pytest.mark.parametrize("layout", LAYOUTS)
def test_reads_a_file_written_in_pieces_once_each(tmp_path, layout):
    data = _mcap_bytes(_messages(), **LAYOUTS[layout])
    path = tmp_path / "log.mcap"
    tail = McapTail(path)
    assert tail.poll() == []  # the recorder has not made the file yet
    read = []
    pieces = random.Random(5)
    with open(path, "wb", buffering=0) as out:
        position = 0
        while position < len(data):
            step = pieces.randint(1, 3000)
            out.write(data[position : position + step])
            position += step
            read += tail.poll()
    tail.close()
    assert read == _messages()
    assert tail.done


def test_a_file_cut_short_gives_its_complete_records(tmp_path):
    data = _mcap_bytes(_messages(), use_chunking=False)
    path = tmp_path / "log.mcap"
    path.write_bytes(data[: len(data) // 2])
    read, done = _read_all(path)
    assert not done
    assert 0 < len(read) < len(_messages())
    assert read == _messages()[: len(read)]


def test_refuses_a_file_that_is_not_mcap(tmp_path):
    path = tmp_path / "log.mcap"
    path.write_bytes(b"not an mcap file at all")
    with pytest.raises(ValueError, match="not an MCAP file"):
        _read_all(path)


# Sealing on the clock, with a recorder played on a fake clock.


class Recorder:
    """Plays ``ros2 bag record``: writes each message once the fake clock reaches its time.

    With *dies_after*, it stops after that many messages without finishing the file, so the
    chunk it was filling never reaches the disk.
    """

    def __init__(self, path: Path, messages, dies_after: int | None = None, **options) -> None:
        self.now = messages[0][1] - 500 * MS
        self._file = open(path, "wb")  # flushed after every message, as a prompt recorder would
        self._writer = Writer(self._file, **options)
        self._writer.start()
        self._schema = self._writer.register_schema(name="raw", encoding="", data=b"")
        self._channels: dict[str, int] = {}
        self._waiting = list(messages)
        self._dies_after = dies_after
        self.written = 0

    def clock(self) -> int:
        return self.now

    def sleep(self, seconds: float) -> None:
        self.now += int(seconds * SECOND)
        while self._waiting and self._waiting[0][1] <= self.now:
            if self.written == self._dies_after:
                self._waiting = []
                return
            topic, log_time, payload = self._waiting.pop(0)
            if topic not in self._channels:
                self._channels[topic] = self._writer.register_channel(topic, "", self._schema)
            self._writer.add_message(self._channels[topic], log_time, payload, log_time)
            self._file.flush()
            self.written += 1
        if not self._waiting and self._dies_after is None and not self._file.closed:
            self._writer.finish()
            self._file.close()

    def close(self) -> None:
        self._file.close()


def _seal_live(path: Path, recorder: Recorder, grace_s: float, idle_s: float = 5.0):
    """Seal while *recorder* writes. *idle_s* is fake time, so a broken test ends, not hangs."""
    identity = generate_key()
    keys, record = begin_segment(TASK, "robot", 100, SECOND, BLOCK, identity)
    heads: list[dict] = []
    sealer = StreamSealer(
        TASK,
        SECOND,
        keys.sign_only,
        start_hash(record),
        persist=heads.append,
        erase=keys.erase,
        reorder_ns=100 * MS,
        grace_ns=int(grace_s * SECOND),
    )
    tail = McapTail(path)
    stats = seal_growing_log(
        tail, sealer, clock=recorder.clock, sleep=recorder.sleep, poll_s=0.05, idle_s=idle_s
    )
    tail.close()
    recorder.close()
    on_disk, _ = _read_all(path)
    segment = Segment(record, keys.public_keys, heads, on_disk)
    result = verify_task([segment], TASK, BLOCK, public_pem(identity), [start_hash(record)])
    return stats, segment, result


def test_grace_longer_than_a_chunk_keeps_every_message_in_its_epoch(tmp_path):
    path = tmp_path / "log.mcap"
    recorder = Recorder(path, _messages(), chunk_size=4096)  # a chunk about every second
    stats, segment, result = _seal_live(path, recorder, grace_s=2.0)
    assert (result.ok, result.late_messages) == (True, 0)
    assert stats.finished and stats.messages == len(_messages()) and stats.chunks > 3
    assert 0.5 < stats.summary()["read_delay"]["max_ms"] / 1000 < 2.0


def test_grace_shorter_than_a_chunk_makes_messages_late(tmp_path):
    path = tmp_path / "log.mcap"
    recorder = Recorder(path, _messages(), chunk_size=16384)  # a chunk every few seconds
    _, segment, result = _seal_live(path, recorder, grace_s=0.5)
    assert any(head["late"] for head in segment.heads)
    assert (result.ok, result.reason) == (False, "a message was sealed too long after its time")


def test_without_chunks_the_sealer_keeps_up(tmp_path):
    path = tmp_path / "log.mcap"
    recorder = Recorder(path, _messages(), use_chunking=False)
    stats, _, result = _seal_live(path, recorder, grace_s=0.5)
    assert result.ok
    summary = stats.summary()
    assert summary["read_delay"]["max_ms"] <= 50
    assert summary["head_delay"]["max_ms"] <= 200  # the 100 ms reorder allowance plus a poll


def test_a_recorder_that_dies_leaves_an_unfinished_seal(tmp_path):
    path = tmp_path / "log.mcap"
    recorder = Recorder(path, _messages(), dies_after=70, use_chunking=False)
    stats, segment, result = _seal_live(path, recorder, grace_s=0.5, idle_s=1.0)
    assert not stats.finished
    assert (result.ok, result.reason) == (False, "the final head is missing")
    assert check_heads(
        segment.heads, TASK, epoch_checker(segment.public_keys), segment.heads[0]["start"], False
    ).ok
    assert check_log(segment.messages, segment.heads, allow_tail=True).ok


def test_a_recorder_on_another_clock_is_refused(tmp_path):
    path = tmp_path / "log.mcap"
    path.write_bytes(_mcap_bytes(_messages(), use_chunking=False))  # stamped in 2023
    sealer = StreamSealer(TASK, SECOND, lambda epoch, message: b"")
    tail = McapTail(path)
    with pytest.raises(ValueError, match="same clock"):
        seal_growing_log(tail, sealer, sleep=lambda seconds: None)
    tail.close()


# The command line, end to end.


def test_seal_then_verify_from_the_command_line(tmp_path):
    path, folder = tmp_path / "log.mcap", tmp_path / "sealed"
    recent = _messages(seconds=3, start_ns=time.time_ns() - 5 * SECOND)
    path.write_bytes(_mcap_bytes(recent, chunk_size=4096))
    command = [sys.executable, "-m", "veriseal.tail", "seal", str(path), "--out-dir", str(folder)]
    done = subprocess.run(
        command + ["--max-seconds", "60", "--poll-ms", "5"],
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert done.returncode == 0, done.stderr
    assert "final head written" in done.stdout
    assert main(["verify", str(path), "--out-dir", str(folder)]) == 0
    assert check_sealed(path, folder).ok
    changed = list(recent)
    changed[7] = (changed[7][0], changed[7][1], b"forged")
    path.write_bytes(_mcap_bytes(changed, chunk_size=4096))
    assert main(["verify", str(path), "--out-dir", str(folder)]) == 1

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
from veriseal.tail import McapTail, SplitTail, check_sealed, main, seal_growing_log, split_files

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


# A recording the recorder splits into several files.


def _split(tmp_path, messages, parts: int = 2) -> list[Path]:
    size = len(messages) // parts
    paths = []
    for part in range(parts):
        chunk = messages[part * size : None if part == parts - 1 else (part + 1) * size]
        paths.append(tmp_path / f"rec_{part}.mcap")
        paths[-1].write_bytes(_mcap_bytes(chunk, use_chunking=False))
    return paths


def test_a_split_recording_is_read_across_its_files(tmp_path):
    messages = _messages()
    paths = _split(tmp_path, messages, parts=3)
    assert split_files(paths[0]) == paths
    tail = SplitTail(paths[0], wait_s=0)
    read = tail.poll()
    tail.poll()
    tail.close()
    assert read == messages
    assert (tail.files, tail.done) == (3, True)


def test_the_sealer_waits_for_the_next_file_before_ending(tmp_path):
    messages = _messages()
    first, second = tmp_path / "rec_0.mcap", tmp_path / "rec_1.mcap"
    first.write_bytes(_mcap_bytes(messages[:60], use_chunking=False))
    now = [0.0]
    tail = SplitTail(first, wait_s=2.0, clock=lambda: now[0])
    assert tail.poll() == messages[:60] and not tail.done
    now[0] = 1.0
    second.write_bytes(_mcap_bytes(messages[60:], use_chunking=False))
    assert tail.poll() == messages[60:] and not tail.done
    now[0] = 2.5
    assert tail.poll() == [] and not tail.done  # the wait starts again after each file
    now[0] = 4.6
    assert tail.poll() == [] and tail.done
    tail.close()


def test_a_file_without_a_number_ends_the_recording_at_once(tmp_path):
    path = tmp_path / "log.mcap"
    path.write_bytes(_mcap_bytes(_messages(), use_chunking=False))
    tail = SplitTail(path)
    tail.poll()
    tail.close()
    assert tail.done


def test_a_split_recording_seals_and_verifies_from_the_command_line(tmp_path):
    folder = tmp_path / "sealed"
    recent = _messages(seconds=4, start_ns=time.time_ns() - 6 * SECOND)
    paths = _split(tmp_path, recent)
    options = ["--max-seconds", "60", "--poll-ms", "5", "--split-wait-seconds", "0.2"]
    assert main(["seal", str(paths[0]), "--out-dir", str(folder), *options]) == 0
    assert main(["verify", str(paths[0]), "--out-dir", str(folder)]) == 0
    paths[1].unlink()
    assert main(["verify", str(paths[0]), "--out-dir", str(folder)]) == 1


# A log that matches its heads but was sealed late.


def test_a_log_sealed_late_has_its_own_verdict(tmp_path, capsys):
    path, folder = tmp_path / "log.mcap", tmp_path / "sealed"
    recent = _messages(seconds=3, start_ns=time.time_ns() - 5 * SECOND)
    straggler = ("/t9", recent[4][1], b"written two seconds after its time")
    path.write_bytes(_mcap_bytes(recent + [straggler], use_chunking=False))
    seal = ["seal", str(path), "--out-dir", str(folder), "--max-seconds", "60", "--poll-ms", "5"]
    assert main(seal + ["--reorder-ms", "0"]) == 0
    assert "after their epoch had closed" in capsys.readouterr().out
    assert main(["verify", str(path), "--out-dir", str(folder)]) == 2
    assert capsys.readouterr().out.startswith("LATE: the log matches every head, but 1 messages")
    assert main(["verify", str(path), "--out-dir", str(folder), "--max-lag-ms", "5000"]) == 0
    unbounded = check_sealed(path, folder, max_lag_ns=None)
    assert unbounded.ok and unbounded.max_late_ns > SECOND
    changed = recent[:7] + [(recent[7][0], recent[7][1], b"forged")] + recent[8:] + [straggler]
    path.write_bytes(_mcap_bytes(changed, use_chunking=False))
    assert main(["verify", str(path), "--out-dir", str(folder)]) == 1
